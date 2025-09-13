require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  PutCommand,
  ScanCommand,
  GetCommand,
  UpdateCommand,
  DeleteCommand
} = require("@aws-sdk/lib-dynamodb");
const {
  RekognitionClient,
  CreateCollectionCommand,
  IndexFacesCommand,
  SearchFacesByImageCommand,
  DetectFacesCommand
} = require("@aws-sdk/client-rekognition");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());

/* ------------------ Thresholds ------------------ */
const FACE_MATCH_THRESHOLD = Number(process.env.FACE_MATCH_THRESHOLD) || 50;
const SUSPICIOUS_THRESHOLD = Number(process.env.SUSPICIOUS_THRESHOLD) || 80;

/* ------------------ DynamoDB Config ------------------ */
const ddbClient = new DynamoDBClient({
  region: process.env.DYNAMODB_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
const dynamoDB = DynamoDBDocumentClient.from(ddbClient);

/* ------------------ Rekognition Config ------------------ */
const rekognition = new RekognitionClient({
  region: process.env.REKOGNITION_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

/* ------------------ Helper: Ensure all users have 'approved' field ------------------ */
async function ensureApprovedField() {
  try {
    const data = await dynamoDB.send(new ScanCommand({ TableName: process.env.DYNAMODB_TABLE }));
    for (const item of data.Items) {
      if (item.approved === undefined) {
        await dynamoDB.send(new UpdateCommand({
          TableName: process.env.DYNAMODB_TABLE,
          Key: { userId: item.userId },
          UpdateExpression: "SET approved = :a",
          ExpressionAttributeValues: { ":a": false },
        }));
      }
    }
    console.log("✅ All missing 'approved' fields updated!");
  } catch (err) {
    console.error("Error updating approved fields:", err);
  }
}

/* ------------------ Root ------------------ */
app.get("/", (req, res) => res.send("✅ Face Recognition Backend Running"));

/* ------------------ Register User ------------------ */
app.post("/registerUserLive", async (req, res) => {
  const { userId, name, email, password, role, imageBase64 } = req.body;
  if (!userId || !name || !password || !imageBase64)
    return res.status(400).json({ success: false, error: "userId, name, password, and imageBase64 required" });

  try {
    const existingUser = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId } }));
    if (existingUser.Item) return res.status(400).json({ success: false, error: "User ID already registered" });

    const imageBuffer = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");

    // Detect face
    const detectResponse = await rekognition.send(new DetectFacesCommand({ Image: { Bytes: imageBuffer }, Attributes: ["DEFAULT"] }));
    const faceCount = detectResponse.FaceDetails.length;
    if (faceCount === 0) return res.status(400).json({ success: false, error: "No face detected." });
    if (faceCount > 1) return res.status(400).json({ success: false, error: "More than one face detected." });

    // Check duplicate face
    const searchResponse = await rekognition.send(new SearchFacesByImageCommand({
      CollectionId: process.env.REKOGNITION_COLLECTION_ID,
      Image: { Bytes: imageBuffer },
      MaxFaces: 1,
      FaceMatchThreshold: FACE_MATCH_THRESHOLD
    }));
    if (searchResponse.FaceMatches?.length > 0) return res.status(400).json({ success: false, error: "Face already registered" });

    // Add user as pending
    await dynamoDB.send(new PutCommand({
      TableName: process.env.DYNAMODB_TABLE,
      Item: { userId, name, email: email || "no-email@example.com", password, role: role || "student", approved: false, faceId: "dummy-face-id" }
    }));

    const indexResponse = await rekognition.send(new IndexFacesCommand({
      CollectionId: process.env.REKOGNITION_COLLECTION_ID,
      Image: { Bytes: imageBuffer },
      ExternalImageId: userId,
      DetectionAttributes: ["DEFAULT"]
    }));

    const faceId = indexResponse.FaceRecords[0]?.Face?.FaceId;
    if (!faceId) return res.status(500).json({ success: false, error: "No face detected during indexing" });

    await dynamoDB.send(new UpdateCommand({
      TableName: process.env.DYNAMODB_TABLE,
      Key: { userId },
      UpdateExpression: "SET faceId = :f",
      ExpressionAttributeValues: { ":f": faceId }
    }));

    res.json({ success: true, message: "Registration pending admin approval", userId, role: role || "student" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ------------------ Login ------------------ */
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ success: false, error: "userId and password required" });

  try {
    const user = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId } }));
    if (!user.Item) return res.status(404).json({ success: false, error: "User not found" });
    if (user.Item.password !== password) return res.status(401).json({ success: false, error: "Incorrect password" });
    if (!user.Item.approved) return res.status(403).json({ success: false, error: "Pending approval by admin" });

    res.json({ success: true, message: "Login successful", userId, role: user.Item.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ------------------ Admin Routes ------------------ */
app.get("/admin/pending", async (req, res) => {
  try {
    const data = await dynamoDB.send(new ScanCommand({
      TableName: process.env.DYNAMODB_TABLE,
      FilterExpression: "approved = :a",
      ExpressionAttributeValues: { ":a": false },
      ProjectionExpression: "#uid, #nm, #rl",
      ExpressionAttributeNames: { "#uid": "userId", "#nm": "name", "#rl": "role" }
    }));
    const pendingUsers = (data.Items || []).map(u => ({ userId: u.userId, name: u.name, role: u.role || 'student' }));
    res.json({ success: true, pending: pendingUsers });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/admin/approve", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ success: false, error: "userId required" });
  try {
    await dynamoDB.send(new UpdateCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId }, UpdateExpression: "SET approved = :a", ExpressionAttributeValues: { ":a": true } }));
    res.json({ success: true, message: "User approved" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/admin/reject", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ success: false, error: "userId required" });
  try {
    await dynamoDB.send(new DeleteCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId } }));
    res.json({ success: true, message: "User rejected" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ------------------ Rekognition Collection ------------------ */
app.get("/create-collection", async (req, res) => {
  try {
    const response = await rekognition.send(new CreateCollectionCommand({ CollectionId: process.env.REKOGNITION_COLLECTION_ID }));
    res.json({ success: true, data: response });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ------------------ Face Attendance ------------------ */
app.post("/markAttendanceLive", async (req, res) => {
  const { imageBase64, userId } = req.body;
  if (!imageBase64 || !userId)
    return res.status(400).json({ success: false, error: "Image and userId required" });

  const imageBuffer = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");

  try {
    const userResp = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId } }));
    if (!userResp.Item) return res.json({ success: false, message: "User not found", suspicious: true });
    if (!userResp.Item.approved) return res.json({ success: false, message: "User not approved", suspicious: true });

    // Detect face
    const detectResponse = await rekognition.send(new DetectFacesCommand({ Image: { Bytes: imageBuffer }, Attributes: ["ALL"] }));
    const faceCount = detectResponse.FaceDetails.length;
    if (faceCount === 0) return res.json({ success: false, message: "No face detected", suspicious: true });
    if (faceCount > 1) return res.json({ success: false, message: "Multiple faces detected", suspicious: true });

    // Check face match
    const searchResponse = await rekognition.send(new SearchFacesByImageCommand({
      CollectionId: process.env.REKOGNITION_COLLECTION_ID,
      Image: { Bytes: imageBuffer },
      MaxFaces: 5,
      FaceMatchThreshold: FACE_MATCH_THRESHOLD
    }));

    const matchedFace = searchResponse.FaceMatches?.find(f => f.Face.ExternalImageId === userId);
    if (!matchedFace) return res.json({ success: false, message: "Face does not match!", suspicious: true });

    const similarity = matchedFace.Similarity;
    const suspicious = similarity < SUSPICIOUS_THRESHOLD;

    // Teacher role: generate QR session
    if (userResp.Item.role === "teacher") {
      const sessionId = uuidv4();
      const qrToken = uuidv4();
      const now = new Date();
      const validUntil = new Date(now.getTime() + 10 * 60 * 1000).toISOString(); // 10 minutes session
      const qrExpiresAt = new Date(now.getTime() + 20 * 1000).toISOString(); // QR valid 10 sec

      const session = {
        sessionId,
        teacherId: userId,
        classId: "classId-placeholder",
        validUntil,
        qrToken,
        qrExpiresAt
      };

      await dynamoDB.send(new PutCommand({ TableName: process.env.DYNAMODB_SESSIONS_TABLE, Item: session }));

      return res.json({
        success: true,
        message: "Teacher recognized, QR session created",
        similarity,
        suspicious,
        session: { sessionId, qrToken, validUntil, qrExpiresAt }
      });
    }

    // Student role: mark attendance
    const today = new Date().toISOString().split("T")[0];
    const existing = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_ATTENDANCE_TABLE, Key: { userId, date: today } }));
    if (existing.Item) return res.json({ success: true, message: "Attendance already marked", similarity, suspicious: false });

    await dynamoDB.send(new PutCommand({
      TableName: process.env.DYNAMODB_ATTENDANCE_TABLE,
      Item: { userId, date: today, timestamp: new Date().toISOString(), status: suspicious ? "Present (Low Confidence)" : "Present", similarity, suspicious }
    }));

    res.json({ success: true, message: "Attendance marked", similarity, suspicious });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message, suspicious: true });
  }
});

/* ------------------ Teacher Session & QR ------------------ */
app.post("/teacher/createSession", async (req, res) => {
  const { teacherId, classId, durationMinutes } = req.body;
  if (!teacherId || !classId)
    return res.status(400).json({ success: false, error: "teacherId & classId required" });

  try {
    const now = new Date();
    const validUntil = new Date(now.getTime() + (durationMinutes || 10) * 60 * 1000).toISOString();
    const sessionId = uuidv4();
    const qrToken = uuidv4();
    const qrExpiresAt = new Date(now.getTime() + 20 * 1000).toISOString();

    const session = { sessionId, teacherId, classId, validUntil, qrToken, qrExpiresAt };

    await dynamoDB.send(new PutCommand({
      TableName: process.env.DYNAMODB_SESSIONS_TABLE,
      Item: session
    }));

    res.json({ success: true, session });
  } catch (err) {
    console.error("Create session error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/teacher/getSession/:classId", async (req, res) => {
  const { classId } = req.params;
  try {
    const now = new Date();

    const result = await dynamoDB.send(new ScanCommand({
      TableName: process.env.DYNAMODB_SESSIONS_TABLE,
      FilterExpression: "classId = :c AND validUntil > :now",
      ExpressionAttributeValues: { ":c": classId, ":now": now.toISOString() }
    }));

    if (!result.Items || result.Items.length === 0) {
      return res.json({ success: false, message: "No active session" });
    }

    let session = result.Items[0];

    if (!session.qrExpiresAt || new Date(session.qrExpiresAt) <= now) {
      session.qrToken = uuidv4();
      session.qrExpiresAt = new Date(now.getTime() + 20 * 1000).toISOString();

      await dynamoDB.send(new PutCommand({
        TableName: process.env.DYNAMODB_SESSIONS_TABLE,
        Item: session
      }));
    }

    res.json({
      success: true,
      session: {
        sessionId: session.sessionId,
        classId: session.classId,
        teacherId: session.teacherId,
        validUntil: session.validUntil,
        qrToken: session.qrToken,
        qrExpiresAt: session.qrExpiresAt
      }
    });
  } catch (err) {
    console.error("Get session error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ------------------ QR Attendance ------------------ */
app.post("/attendance/mark", async (req, res) => {
  const { userId, sessionId, qrToken } = req.body;
  if (!userId || !sessionId || !qrToken)
    return res.status(400).json({ success: false, error: "userId, sessionId & qrToken required" });

  try {
    const userResp = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId } }));
    if (!userResp.Item) return res.status(404).json({ success: false, error: "User not found" });
    if (!userResp.Item.approved) return res.status(403).json({ success: false, error: "User not approved" });

    const sessionResp = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_SESSIONS_TABLE, Key: { sessionId } }));
    if (!sessionResp.Item) return res.status(404).json({ success: false, error: "Session not found" });

    const now = new Date();
    if (new Date(sessionResp.Item.validUntil) < now) return res.status(400).json({ success: false, error: "Session expired" });
    if (sessionResp.Item.qrToken !== qrToken || new Date(sessionResp.Item.qrExpiresAt) < now)
      return res.status(400).json({ success: false, error: "Invalid or expired QR" });

    const today = new Date().toISOString().split("T")[0];
    const existing = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_ATTENDANCE_TABLE, Key: { userId, date: today } }));
    if (existing.Item) return res.json({ success: true, message: "Attendance already marked" });

    await dynamoDB.send(new PutCommand({
      TableName: process.env.DYNAMODB_ATTENDANCE_TABLE,
      Item: { userId, date: today, sessionId, timestamp: now.toISOString(), status: "Present" }
    }));

    res.json({ success: true, message: "Attendance marked via QR" });
  } catch (err) {
    console.error("QR Attendance error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ------------------ Teacher Submit Attendance ------------------ */
app.post("/teacher/submitAttendance", async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ success: false, error: "sessionId required" });

  try {
    const sessionResp = await dynamoDB.send(new GetCommand({
      TableName: process.env.DYNAMODB_SESSIONS_TABLE,
      Key: { sessionId }
    }));
    if (!sessionResp.Item) return res.status(404).json({ success: false, error: "Session not found" });

    await dynamoDB.send(new UpdateCommand({
      TableName: process.env.DYNAMODB_SESSIONS_TABLE,
      Key: { sessionId },
      UpdateExpression: "SET finalized = :f",
      ExpressionAttributeValues: { ":f": true }
    }));

    res.json({ success: true, message: "Attendance finalized!" });
  } catch (err) {
    console.error("Submit attendance error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ------------------ Start Server ------------------ */
ensureApprovedField().then(() => {
  const PORT = process.env.PORT || 5002;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`))
     .on('error', (err) => {
       if (err.code === 'EADDRINUSE') {
         console.error(`Port ${PORT} already in use. Kill existing process or change PORT.`);
       } else console.error(err);
     });
});

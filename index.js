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
  QueryCommand,
} = require("@aws-sdk/lib-dynamodb");
const {
  RekognitionClient,
  IndexFacesCommand,
  SearchFacesByImageCommand,
  DetectFacesCommand,
} = require("@aws-sdk/client-rekognition");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());

const FACE_MATCH_THRESHOLD = Number(process.env.FACE_MATCH_THRESHOLD) || 50;

const ddbClient = new DynamoDBClient({
  region: process.env.DYNAMODB_REGION || process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
const dynamoDB = DynamoDBDocumentClient.from(ddbClient);

const rekognition = new RekognitionClient({
  region: process.env.REKOGNITION_REGION || process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

/* helper to ensure approved field exists */
async function ensureApprovedField() {
  try {
    if (!process.env.DYNAMODB_TABLE) return;
    const data = await dynamoDB.send(new ScanCommand({ TableName: process.env.DYNAMODB_TABLE }));
    for (const item of data.Items || []) {
      if (item.approved === undefined) {
        await dynamoDB.send(
          new UpdateCommand({
            TableName: process.env.DYNAMODB_TABLE,
            Key: { userId: item.userId },
            UpdateExpression: "SET approved = :a",
            ExpressionAttributeValues: { ":a": false },
          })
        );
      }
    }
    console.log("✅ All missing 'approved' fields updated!");
  } catch (err) {
    console.error("Error updating approved fields:", err);
  }
}

app.get("/", (req, res) => res.send("✅ Face Recognition Backend Running"));

/* register */
app.post("/registerUserLive", async (req, res) => {
  const { userId, name, email, password, role, imageBase64 } = req.body;
  if (!userId || !name || !password || !imageBase64) return res.status(400).json({ success: false, error: "userId,name,password,imageBase64 required" });

  try {
    const existing = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId } }));
    if (existing.Item) return res.status(400).json({ success: false, error: "User ID already registered" });

    const imageBuffer = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
    const detectResp = await rekognition.send(new DetectFacesCommand({ Image: { Bytes: imageBuffer }, Attributes: ["DEFAULT"] }));
    if ((detectResp.FaceDetails || []).length !== 1) return res.status(400).json({ success: false, error: "Image must contain exactly 1 face" });

    const duplicate = await rekognition.send(new SearchFacesByImageCommand({
      CollectionId: process.env.REKOGNITION_COLLECTION_ID,
      Image: { Bytes: imageBuffer },
      MaxFaces: 1,
      FaceMatchThreshold: FACE_MATCH_THRESHOLD,
    }));
    if (duplicate.FaceMatches?.length > 0) return res.status(400).json({ success: false, error: "Face already registered" });

    await dynamoDB.send(new PutCommand({
      TableName: process.env.DYNAMODB_TABLE,
      Item: { userId, name, email: email || "no-email@example.com", password, role: role || "student", approved: false, faceId: "pending" },
    }));

    const idx = await rekognition.send(new IndexFacesCommand({
      CollectionId: process.env.REKOGNITION_COLLECTION_ID,
      Image: { Bytes: imageBuffer },
      ExternalImageId: userId,
      DetectionAttributes: ["DEFAULT"],
    }));
    const faceId = idx.FaceRecords?.[0]?.Face?.FaceId;
    if (!faceId) return res.status(500).json({ success: false, error: "Failed to index face" });

    await dynamoDB.send(new UpdateCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId }, UpdateExpression: "SET faceId = :f", ExpressionAttributeValues: { ":f": faceId } }));
    res.json({ success: true, message: "Registration pending admin approval", userId, role: role || "student" });
  } catch (err) {
    console.error("registerUserLive error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* login */
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ success: false, error: "userId & password required" });

  try {
    const u = await dynamoDB.send(new GetCommand({ TableName: process.env.DYNAMODB_TABLE, Key: { userId } }));
    if (!u.Item) return res.status(404).json({ success: false, error: "User not found" });
    if (u.Item.password !== password) return res.status(401).json({ success: false, error: "Incorrect password" });
    if (!u.Item.approved) return res.status(403).json({ success: false, error: "Pending approval by admin" });

    res.json({ success: true, message: "Login successful", userId, role: u.Item.role });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* verify face only (no session) */
app.post("/verifyFaceOnly", async (req, res) => {
  const { userId, imageBase64 } = req.body;
  if (!userId || !imageBase64) return res.status(400).json({ success: false, error: "userId & imageBase64 required" });

  try {
    const buf = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
    const sr = await rekognition.send(new SearchFacesByImageCommand({
      CollectionId: process.env.REKOGNITION_COLLECTION_ID, Image: { Bytes: buf }, MaxFaces: 1, FaceMatchThreshold: FACE_MATCH_THRESHOLD,
    }));
    const fm = sr.FaceMatches?.[0];
    if (!fm || fm.Face?.ExternalImageId !== userId) return res.json({ success: false, error: "Face does not match user ID" });
    return res.json({ success: true, message: "Face verified" });
  } catch (err) {
    console.error("verifyFaceOnly error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* mark attendance (student) */
app.post("/markAttendanceLive", async (req, res) => {
  const { sessionId, userId, imageBase64 } = req.body;
  if (!sessionId || !userId || !imageBase64) return res.status(400).json({ success: false, error: "sessionId,userId,imageBase64 required" });

  try {
    const buf = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
    const sr = await rekognition.send(new SearchFacesByImageCommand({
      CollectionId: process.env.REKOGNITION_COLLECTION_ID, Image: { Bytes: buf }, MaxFaces: 1, FaceMatchThreshold: FACE_MATCH_THRESHOLD,
    }));
    const fm = sr.FaceMatches?.[0];
    if (!fm || fm.Face?.ExternalImageId !== userId) return res.json({ success: false, error: "Face does not match user ID" });

    // Put attendance (sessionId + userId)
    const att = { sessionId, userId, status: "present", finalized: false, timestamp: new Date().toISOString() };
    await dynamoDB.send(new PutCommand({ TableName: process.env.DYNAMODB_ATTENDANCE_TABLE, Item: att }));
    res.json({ success: true, message: "Attendance marked (pending teacher finalization)" });
  } catch (err) {
    console.error("markAttendanceLive error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* teacher create session */
app.post("/teacher/createSession", async (req, res) => {
  const { teacherId, classId, durationMinutes } = req.body;
  if (!teacherId || !classId) return res.status(400).json({ success: false, error: "teacherId & classId required" });

  try {
    const now = new Date();
    const validUntil = new Date(now.getTime() + (durationMinutes || 10) * 60 * 1000).toISOString();
    const sessionId = uuidv4();
    const qrToken = uuidv4();
    const qrExpiresAt = new Date(now.getTime() + 20 * 1000).toISOString();
    const session = { sessionId, teacherId, classId, validUntil, qrToken, qrExpiresAt, finalized: false };
    await dynamoDB.send(new PutCommand({ TableName: process.env.DYNAMODB_SESSIONS_TABLE, Item: session }));
    res.json({ success: true, session });
  } catch (err) {
    console.error("teacher/createSession error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* teacher get session (by classId) */
app.get("/teacher/getSession/:classId", async (req, res) => {
  const { classId } = req.params;
  try {
    const sr = await dynamoDB.send(new QueryCommand({
      TableName: process.env.DYNAMODB_SESSIONS_TABLE,
      IndexName: "classId-index", // ensure GSI exists
      KeyConditionExpression: "classId = :c",
      ExpressionAttributeValues: { ":c": classId },
      Limit: 1,
      ScanIndexForward: false,
    }));
    if (!sr.Items || !sr.Items.length) return res.json({ success: false, error: "No active session" });
    const session = sr.Items[0];
    const now = new Date();
    if (!session.qrExpiresAt || new Date(session.qrExpiresAt) <= now) {
      session.qrToken = uuidv4();
      session.qrExpiresAt = new Date(now.getTime() + 20 * 1000).toISOString();
      await dynamoDB.send(new PutCommand({ TableName: process.env.DYNAMODB_SESSIONS_TABLE, Item: session }));
    }
    return res.json({ success: true, session: { sessionId: session.sessionId, classId: session.classId, teacherId: session.teacherId, validUntil: session.validUntil, qrToken: session.qrToken, qrExpiresAt: session.qrExpiresAt, finalized: session.finalized || false } });
  } catch (err) {
    console.error("teacher/getSession error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* view attendance by sessionId */
app.get("/teacher/viewAttendance/:sessionId", async (req, res) => {
  const { sessionId } = req.params;
  try {
    const ar = await dynamoDB.send(new QueryCommand({
      TableName: process.env.DYNAMODB_ATTENDANCE_TABLE,
      IndexName: "sessionId-index",
      KeyConditionExpression: "sessionId = :s",
      ExpressionAttributeValues: { ":s": sessionId },
    }));
    res.json({ success: true, attendance: ar.Items || [] });
  } catch (err) {
    console.error("viewAttendance error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* finalize attendance (teacher) */
app.post("/teacher/finalizeAttendance", async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ success: false, error: "sessionId required" });

  try {
    await dynamoDB.send(new UpdateCommand({ TableName: process.env.DYNAMODB_SESSIONS_TABLE, Key: { sessionId }, UpdateExpression: "SET finalized = :f", ExpressionAttributeValues: { ":f": true } }));

    const ar = await dynamoDB.send(new QueryCommand({
      TableName: process.env.DYNAMODB_ATTENDANCE_TABLE,
      IndexName: "sessionId-index",
      KeyConditionExpression: "sessionId = :s",
      ExpressionAttributeValues: { ":s": sessionId },
    }));

    const updates = (ar.Items || []).map((it) => dynamoDB.send(new UpdateCommand({
      TableName: process.env.DYNAMODB_ATTENDANCE_TABLE,
      Key: { sessionId: it.sessionId, userId: it.userId },
      UpdateExpression: "SET finalized = :f",
      ExpressionAttributeValues: { ":f": true },
    })));

    if (updates.length) await Promise.all(updates);
    res.json({ success: true, message: "Attendance finalized", sessionId });
  } catch (err) {
    console.error("finalizeAttendance error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* start */
ensureApprovedField().then(() => {
  const PORT = process.env.PORT || 5002;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
});

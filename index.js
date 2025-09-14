// server.js
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

/* ------------------ Config / Thresholds ------------------ */
// Face match threshold (higher is stricter). Can be overridden via env.
const FACE_MATCH_THRESHOLD = Number(process.env.FACE_MATCH_THRESHOLD) || 80;
// How long a QR token is valid (seconds). Default 60s.
const QR_EXPIRE_SECONDS = Number(process.env.QR_EXPIRE_SECONDS) || 60;

const USERS_TABLE = process.env.DYNAMODB_TABLE;
const ATT_TABLE = process.env.DYNAMODB_ATTENDANCE_TABLE;
const SESSIONS_TABLE = process.env.DYNAMODB_SESSIONS_TABLE;
const REK_COLLECTION = process.env.REKOGNITION_COLLECTION_ID;

if (!USERS_TABLE || !ATT_TABLE || !SESSIONS_TABLE || !REK_COLLECTION) {
  console.warn(
    "Warning: One or more required environment variables missing: DYNAMODB_TABLE, DYNAMODB_ATTENDANCE_TABLE, DYNAMODB_SESSIONS_TABLE, REKOGNITION_COLLECTION_ID"
  );
}

/* ------------------ DynamoDB Client ------------------ */
const ddbClient = new DynamoDBClient({
  region: process.env.DYNAMODB_REGION || process.env.AWS_REGION || "us-east-1",
  credentials:
    process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY
      ? {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        }
      : undefined,
});
const dynamoDB = DynamoDBDocumentClient.from(ddbClient);

/* ------------------ Rekognition Client ------------------ */
const rekognition = new RekognitionClient({
  region: process.env.REKOGNITION_REGION || process.env.AWS_REGION || "us-east-1",
  credentials:
    process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY
      ? {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        }
      : undefined,
});

/* ------------------ Helper: Ensure approved field exists for users ------------------ */
async function ensureApprovedField() {
  try {
    if (!USERS_TABLE) {
      console.debug("USERS_TABLE not set - skipping ensureApprovedField");
      return;
    }
    const data = await dynamoDB.send(new ScanCommand({ TableName: USERS_TABLE }));
    for (const item of data.Items || []) {
      if (item.approved === undefined) {
        await dynamoDB.send(
          new UpdateCommand({
            TableName: USERS_TABLE,
            Key: { userId: item.userId },
            UpdateExpression: "SET approved = :a",
            ExpressionAttributeValues: { ":a": false },
          })
        );
      }
    }
    console.log("✅ All missing 'approved' fields updated (if any).");
  } catch (err) {
    console.error("ensureApprovedField error:", err);
  }
}

/* ------------------ Root ------------------ */
app.get("/", (req, res) =>
  res.send("✅ Face Recognition Backend Running (finalized attendance support)")
);

/* ------------------ Helper: fetch session by sessionId ------------------ */
async function getSessionById(sessionId) {
  if (!sessionId) return null;
  try {
    const resp = await dynamoDB.send(new GetCommand({ TableName: SESSIONS_TABLE, Key: { sessionId } }));
    return resp.Item || null;
  } catch (err) {
    console.error("getSessionById error:", err);
    return null;
  }
}

/* ------------------ Helper: find active session by classId (prefers GSI) ------------------ */
async function findActiveSessionByClass(classId) {
  if (!classId) return null;
  // try Query using GSI 'classId-index' if exists
  try {
    const q = {
      TableName: SESSIONS_TABLE,
      IndexName: "classId-index",
      KeyConditionExpression: "classId = :c",
      ExpressionAttributeValues: { ":c": classId },
      ScanIndexForward: false,
      Limit: 1,
    };
    const resp = await dynamoDB.send(new QueryCommand(q));
    const items = resp.Items || [];
    const active = items.find((s) => !s.finalized);
    if (active) return active;
  } catch (err) {
    // likely the GSI doesn't exist — fallback to scan
    console.debug("classId-index query failed, falling back to scan:", err.message || err);
  }

  // fallback: scan table and find latest non-finalized session for classId
  try {
    const resp = await dynamoDB.send(new ScanCommand({ TableName: SESSIONS_TABLE }));
    const session = (resp.Items || [])
      .filter((s) => s.classId === classId && !s.finalized)
      .sort((a, b) => new Date(b.validUntil) - new Date(a.validUntil))[0];
    return session || null;
  } catch (err) {
    console.error("findActiveSessionByClass scan error:", err);
    return null;
  }
}

/* ------------------ Face verification endpoint (used by frontends) ------------------ */
app.post("/verifyFaceOnly", async (req, res) => {
  const { userId, imageBase64 } = req.body;
  if (!userId || !imageBase64)
    return res.status(400).json({ success: false, error: "userId and imageBase64 required" });

  try {
    const imageBuffer = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
    const searchResponse = await rekognition.send(
      new SearchFacesByImageCommand({
        CollectionId: REK_COLLECTION,
        Image: { Bytes: imageBuffer },
        MaxFaces: 1,
        FaceMatchThreshold: FACE_MATCH_THRESHOLD,
      })
    );

    const faceMatch = searchResponse.FaceMatches?.[0];
    if (faceMatch && faceMatch.Face?.ExternalImageId === userId) {
      return res.json({ success: true, message: "Face verified" });
    } else {
      return res.json({ success: false, error: "Face not recognized" });
    }
  } catch (err) {
    console.error("verifyFaceOnly error:", err);
    return res.status(500).json({ success: false, error: err.message || "Rekognition error" });
  }
});

/* ------------------ Register user (live) ------------------ */
app.post("/registerUserLive", async (req, res) => {
  const { userId, name, email, password, role, imageBase64 } = req.body;
  if (!userId || !name || !password || !imageBase64)
    return res.status(400).json({ success: false, error: "userId, name, password, and imageBase64 required" });

  try {
    const existingUser = await dynamoDB.send(new GetCommand({ TableName: USERS_TABLE, Key: { userId } }));
    if (existingUser.Item) return res.status(400).json({ success: false, error: "User ID already registered" });

    const imageBuffer = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");

    // Ensure exactly 1 face
    const detectResponse = await rekognition.send(new DetectFacesCommand({ Image: { Bytes: imageBuffer }, Attributes: ["DEFAULT"] }));
    if ((detectResponse.FaceDetails || []).length !== 1)
      return res.status(400).json({ success: false, error: "Image must contain exactly 1 face" });

    // Check duplicates
    const searchResponse = await rekognition.send(
      new SearchFacesByImageCommand({
        CollectionId: REK_COLLECTION,
        Image: { Bytes: imageBuffer },
        MaxFaces: 1,
        FaceMatchThreshold: FACE_MATCH_THRESHOLD,
      })
    );
    if (searchResponse.FaceMatches?.length > 0)
      return res.status(400).json({ success: false, error: "Face already registered" });

    // Create user (pending approval)
    await dynamoDB.send(
      new PutCommand({
        TableName: USERS_TABLE,
        Item: {
          userId,
          name,
          email: email || "no-email@example.com",
          password,
          role: role || "student",
          approved: false,
          faceId: "pending",
        },
      })
    );

    // Index face in Rekognition
    const indexResponse = await rekognition.send(
      new IndexFacesCommand({
        CollectionId: REK_COLLECTION,
        Image: { Bytes: imageBuffer },
        ExternalImageId: userId,
        DetectionAttributes: ["DEFAULT"],
      })
    );

    const faceId = indexResponse.FaceRecords?.[0]?.Face?.FaceId;
    if (!faceId) return res.status(500).json({ success: false, error: "Failed to index face" });

    await dynamoDB.send(
      new UpdateCommand({
        TableName: USERS_TABLE,
        Key: { userId },
        UpdateExpression: "SET faceId = :f",
        ExpressionAttributeValues: { ":f": faceId },
      })
    );

    return res.json({ success: true, message: "Registration pending admin approval", userId, role: role || "student" });
  } catch (err) {
    console.error("registerUserLive error:", err);
    return res.status(500).json({ success: false, error: err.message || "Registration error" });
  }
});

/* ------------------ Login ------------------ */
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password)
    return res.status(400).json({ success: false, error: "userId and password required" });

  try {
    const user = await dynamoDB.send(new GetCommand({ TableName: USERS_TABLE, Key: { userId } }));
    if (!user.Item) return res.status(404).json({ success: false, error: "User not found" });
    if (user.Item.password !== password) return res.status(401).json({ success: false, error: "Incorrect password" });
    if (!user.Item.approved) return res.status(403).json({ success: false, error: "Pending approval by admin" });

    return res.json({ success: true, message: "Login successful", userId, role: user.Item.role });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ success: false, error: err.message || "Login error" });
  }
});

/* ------------------ Mark Attendance (requires valid QR) ------------------ */
app.post("/markAttendanceLive", async (req, res) => {
  const { sessionId, userId, imageBase64, qrToken } = req.body;
  if (!sessionId || !userId || !imageBase64 || !qrToken)
    return res.status(400).json({ success: false, error: "sessionId, userId, imageBase64 and qrToken required" });

  try {
    // Validate session & QR token
    const session = await getSessionById(sessionId);
    if (!session) return res.status(400).json({ success: false, error: "Invalid sessionId" });
    if (session.finalized) return res.status(400).json({ success: false, error: "Session already finalized" });

    // Check token and expiry
    const now = Date.now();
    if (!session.qrToken || session.qrToken !== qrToken) {
      return res.status(400).json({ success: false, error: "QR token invalid" });
    }
    if (!session.qrExpiresAt || new Date(session.qrExpiresAt).getTime() < now) {
      return res.status(400).json({ success: false, error: "QR token expired" });
    }

    // Verify face via Rekognition
    const imageBuffer = Buffer.from(imageBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
    const searchResponse = await rekognition.send(
      new SearchFacesByImageCommand({
        CollectionId: REK_COLLECTION,
        Image: { Bytes: imageBuffer },
        MaxFaces: 1,
        FaceMatchThreshold: FACE_MATCH_THRESHOLD,
      })
    );

    const faceMatch = searchResponse.FaceMatches?.[0];
    if (!faceMatch || faceMatch.Face?.ExternalImageId !== userId)
      return res.status(400).json({ success: false, error: "Face does not match user ID" });

    // Prevent duplicate: check if attendance exists
    try {
      const existing = await dynamoDB.send(
        new GetCommand({ TableName: ATT_TABLE, Key: { sessionId, userId } })
      );
      if (existing.Item) {
        if (existing.Item.finalized) {
          return res.status(400).json({ success: false, error: "Attendance already finalized" });
        }
        return res.json({ success: true, message: "Attendance already marked (pending finalization)" });
      }
    } catch (err) {
      console.warn("check-existing-attendance error:", err);
      // continue to attempt insert
    }

    const attendance = {
      sessionId,
      userId,
      status: "present",
      finalized: false,
      timestamp: new Date().toISOString(),
    };

    await dynamoDB.send(new PutCommand({ TableName: ATT_TABLE, Item: attendance }));

    return res.json({ success: true, message: "Attendance marked (pending teacher finalization)" });
  } catch (err) {
    console.error("markAttendanceLive error:", err);
    return res.status(500).json({ success: false, error: err.message || "Attendance error" });
  }
});

/* ------------------ Teacher Creates Session ------------------ */
app.post("/teacher/createSession", async (req, res) => {
  const { teacherId, classId, durationMinutes } = req.body;
  if (!teacherId || !classId)
    return res.status(400).json({ success: false, error: "teacherId & classId required" });

  try {
    // validate teacher exists and is approved teacher
    const teacher = await dynamoDB.send(new GetCommand({ TableName: USERS_TABLE, Key: { userId: teacherId } }));
    if (!teacher.Item) return res.status(403).json({ success: false, error: "Teacher not found" });
    if (teacher.Item.role !== "teacher") return res.status(403).json({ success: false, error: "User not a teacher" });
    if (!teacher.Item.approved) return res.status(403).json({ success: false, error: "Teacher not approved" });

    const now = new Date();
    const validUntil = new Date(now.getTime() + (durationMinutes || 10) * 60 * 1000).toISOString();
    const sessionId = uuidv4();
    const qrToken = uuidv4();
    const qrExpiresAt = new Date(now.getTime() + QR_EXPIRE_SECONDS * 1000).toISOString();

    const session = { sessionId, teacherId, classId, validUntil, qrToken, qrExpiresAt, finalized: false };

    await dynamoDB.send(new PutCommand({ TableName: SESSIONS_TABLE, Item: session }));

    // Build qrPayload string teacher frontend should encode as the QR
    const qrPayload = JSON.stringify({ sessionId: session.sessionId, qrToken: session.qrToken });

    return res.json({ success: true, session, qrPayload });
  } catch (err) {
    console.error("teacher/createSession error:", err);
    return res.status(500).json({ success: false, error: err.message || "Create session error" });
  }
});

/* ------------------ Teacher Get / Refresh Session by classId ------------------ */
app.get("/teacher/getSession/:classId", async (req, res) => {
  const { classId } = req.params;
  try {
    const session = await findActiveSessionByClass(classId);
    if (!session) return res.json({ success: false, error: "No active session" });

    // rotate QR token and update expiry
    const newToken = uuidv4();
    const newQrExpiresAt = new Date(Date.now() + QR_EXPIRE_SECONDS * 1000).toISOString();

    await dynamoDB.send(
      new UpdateCommand({
        TableName: SESSIONS_TABLE,
        Key: { sessionId: session.sessionId },
        UpdateExpression: "SET qrToken = :q, qrExpiresAt = :e",
        ExpressionAttributeValues: { ":q": newToken, ":e": newQrExpiresAt },
      })
    );

    const updated = { ...session, qrToken: newToken, qrExpiresAt: newQrExpiresAt };
    const qrPayload = JSON.stringify({ sessionId: updated.sessionId, qrToken: updated.qrToken });

    return res.json({ success: true, session: updated, qrPayload });
  } catch (err) {
    console.error("teacher/getSession error:", err);
    return res.status(500).json({ success: false, error: err.message || "Get session error" });
  }
});

/* ------------------ Teacher View Attendance for session ------------------ */
app.get("/teacher/viewAttendance/:sessionId", async (req, res) => {
  const { sessionId } = req.params;
  try {
    const q = {
      TableName: ATT_TABLE,
      IndexName: "sessionId-index",
      KeyConditionExpression: "sessionId = :s",
      ExpressionAttributeValues: { ":s": sessionId },
    };

    let attendanceResp;
    try {
      attendanceResp = await dynamoDB.send(new QueryCommand(q));
    } catch (err) {
      console.debug("sessionId-index query failed, falling back to scan:", err.message || err);
      const scanResp = await dynamoDB.send(new ScanCommand({ TableName: ATT_TABLE }));
      attendanceResp = { Items: (scanResp.Items || []).filter((it) => it.sessionId === sessionId) };
    }

    return res.json({ success: true, attendance: attendanceResp.Items || [] });
  } catch (err) {
    console.error("viewAttendance error:", err);
    return res.status(500).json({ success: false, error: err.message || "View attendance error" });
  }
});

/* ------------------ Teacher Finalize Attendance ------------------ */
app.post("/teacher/finalizeAttendance", async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ success: false, error: "sessionId required" });

  try {
    await dynamoDB.send(
      new UpdateCommand({
        TableName: SESSIONS_TABLE,
        Key: { sessionId },
        UpdateExpression: "SET finalized = :f",
        ExpressionAttributeValues: { ":f": true },
      })
    );

    // fetch attendance entries
    let attendanceResp;
    try {
      attendanceResp = await dynamoDB.send(
        new QueryCommand({
          TableName: ATT_TABLE,
          IndexName: "sessionId-index",
          KeyConditionExpression: "sessionId = :s",
          ExpressionAttributeValues: { ":s": sessionId },
        })
      );
    } catch (err) {
      const scanResp = await dynamoDB.send(new ScanCommand({ TableName: ATT_TABLE }));
      attendanceResp = { Items: (scanResp.Items || []).filter((it) => it.sessionId === sessionId) };
    }

    const items = attendanceResp.Items || [];
    const updates = items.map((it) =>
      dynamoDB.send(
        new UpdateCommand({
          TableName: ATT_TABLE,
          Key: { sessionId: it.sessionId, userId: it.userId },
          UpdateExpression: "SET finalized = :f",
          ExpressionAttributeValues: { ":f": true },
        })
      )
    );

    if (updates.length > 0) await Promise.all(updates);

    return res.json({ success: true, message: "Attendance finalized", sessionId });
  } catch (err) {
    console.error("finalizeAttendance error:", err);
    return res.status(500).json({ success: false, error: err.message || "Finalize error" });
  }
});

/* ------------------ Start Server ------------------ */
ensureApprovedField().then(() => {
  const PORT = process.env.PORT || 5002;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
});

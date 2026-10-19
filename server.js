const express = require('express');
const crypto = require('crypto');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const EvidenceChaincode = require('./chaincode/evidenceContract');

const app = express();
const chaincode = new EvidenceChaincode();
const JWT_SECRET = 'ZUT_HYPERLEDGER_FABRIC_MSP_SECRET_2026';
const COUCHDB_URL = process.env.COUCHDB_URL || 'http://admin:adminpw@127.0.0.1:5984';
const COUCHDB_DB = 'forensic_world_state';

// Ensure Evidence Vault directory exists
const VAULT_DIR = path.join(__dirname, 'evidence_vault');
if (!fs.existsSync(VAULT_DIR)) fs.mkdirSync(VAULT_DIR, { recursive: true });

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/vault', express.static(VAULT_DIR));

const LEDGER_FILE = path.join(__dirname, 'fabric-ledger-store.json');

// Default MSP Identities with Bcrypt-hashed passwords (Default password for all demo accounts: Zut@2026)
function getInitialUsers() {
    const passwordHash = bcrypt.hashSync('Zut@2026', 10);
    return {
        'chanda.zp': {
            username: 'chanda.zp',
            passwordHash,
            fullName: 'Insp. Chanda Mulenga',
            badgeNumber: 'ZP-FR-4092',
            role: 'First Responder',
            mspId: 'ZambiaPoliceMSP',
            department: 'Zambia Police Cybercrime First Response Unit (Ndola)',
            x509Serial: '4A:8F:11:C3:99:01:B2'
        },
        'mutale.lab': {
            username: 'mutale.lab',
            passwordHash,
            fullName: 'Analyst Mutale Banda',
            badgeNumber: 'DFL-AN-1108',
            role: 'Forensic Investigator',
            mspId: 'ForensicLabMSP',
            department: 'National Digital Forensics Laboratory',
            x509Serial: '7B:2E:94:D0:55:19:F4'
        },
        'daka.sup': {
            username: 'daka.sup',
            passwordHash,
            fullName: 'Supt. Daka Phiri',
            badgeNumber: 'SUP-HQ-0081',
            role: 'Supervisor',
            mspId: 'SupervisoryMSP',
            department: 'Forensic Oversight & Internal Audit Directorate',
            x509Serial: '9C:10:6A:E8:31:77:A9'
        },
        'mwamba.court': {
            username: 'mwamba.court',
            passwordHash,
            fullName: 'Hon. Justice K. Mwamba',
            badgeNumber: 'JUD-HC-0014',
            role: 'Judicial Officer',
            mspId: 'JudiciaryMSP',
            department: 'High Court of Zambia (Ndola Division)',
            x509Serial: '1F:6D:33:B7:80:4E:C2'
        }
    };
}

// Load or Create Persistent Blockchain & World State
function loadLedger() {
    if (fs.existsSync(LEDGER_FILE)) {
        return JSON.parse(fs.readFileSync(LEDGER_FILE, 'utf8'));
    }
    const genesisTimestamp = new Date().toISOString();
    const genesisDataHash = crypto.createHash('sha256').update('ZUT_HYPERLEDGER_FABRIC_GENESIS_2026').digest('hex');
    const genesisHeader = `0|0|${genesisDataHash}|GENESIS_TX|${genesisTimestamp}`;
    const genesisBlockHash = crypto.createHash('sha256').update(genesisHeader).digest('hex');

    const initial = {
        channelName: 'zut-forensic-coc-channel',
        couchDbSynced: false,
        users: getInitialUsers(),
        worldState: {},
        blocks: [
            {
                blockNumber: 0,
                txId: 'GENESIS_TX',
                previousBlockHash: '0',
                dataHash: genesisDataHash,
                blockHash: genesisBlockHash,
                mspId: 'OrdererMSP',
                action: 'CHANNEL_GENESIS_BLOCK',
                actor: 'Hyperledger Fabric Orderer Service',
                evidenceId: 'SYSTEM_INIT',
                timestamp: genesisTimestamp
            }
        ]
    };
    fs.writeFileSync(LEDGER_FILE, JSON.stringify(initial, null, 2));
    return initial;
}

function saveLedger(ledger) {
    fs.writeFileSync(LEDGER_FILE, JSON.stringify(ledger, null, 2));
}

// Optional Real CouchDB Synchronization (if Docker container is running on port 5984)
async function syncToCouchDB(docId, docData) {
    try {
        await fetch(`${COUCHDB_URL}/${COUCHDB_DB}`, { method: 'PUT' });
        const existingRes = await fetch(`${COUCHDB_URL}/${COUCHDB_DB}/${encodeURIComponent(docId)}`);
        const payload = { ...docData };
        if (existingRes.ok) {
            const existingDoc = await existingRes.json();
            payload._rev = existingDoc._rev;
        }
        await fetch(`${COUCHDB_URL}/${COUCHDB_DB}/${encodeURIComponent(docId)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return true;
    } catch {
        return false; // CouchDB Docker container not running; local worldState remains authoritative
    }
}

// JWT Authentication Middleware
function authenticateMSP(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required. Please sign in with your MSP credentials.' });
    }
    try {
        const token = authHeader.split(' ')[1];
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired MSP session token. Please log in again.' });
    }
}

// Create Hyperledger Fabric Transaction Context
function createFabricContext(ledger, userProfile, actionName, evidenceId) {
    const txId = crypto.randomBytes(32).toString('hex');
    return {
        clientIdentity: userProfile,
        stub: {
            getTxID: () => txId,
            getState: async (key) => {
                const doc = ledger.worldState[key];
                return doc ? Buffer.from(JSON.stringify(doc)) : null;
            },
            putState: async (key, valueBuffer) => {
                const parsedDoc = JSON.parse(valueBuffer.toString());
                ledger.worldState[key] = parsedDoc;

                const prevBlock = ledger.blocks[ledger.blocks.length - 1];
                const dataHash = crypto.createHash('sha256').update(valueBuffer).digest('hex');
                const blockNumber = prevBlock.blockNumber + 1;
                const timestamp = new Date().toISOString();

                const headerStr = `${blockNumber}|${prevBlock.blockHash}|${dataHash}|${txId}|${timestamp}`;
                const blockHash = crypto.createHash('sha256').update(headerStr).digest('hex');

                ledger.blocks.push({
                    blockNumber,
                    txId,
                    previousBlockHash: prevBlock.blockHash,
                    dataHash,
                    blockHash,
                    mspId: userProfile.mspId,
                    action: actionName,
                    actor: `${userProfile.fullName} (${userProfile.role})`,
                    evidenceId,
                    timestamp
                });

                ledger.couchDbSynced = await syncToCouchDB(key, parsedDoc);
                saveLedger(ledger);
            }
        }
    };
}

// AUTH API 1: Login with MSP Credentials
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const ledger = loadLedger();
    const user = ledger.users[username];

    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
        return res.status(401).json({ error: 'Invalid MSP username or password.' });
    }

    const { passwordHash, ...safeProfile } = user;
    const token = jwt.sign(safeProfile, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: safeProfile });
});

// AUTH API 2: Supervisor Register New MSP Officer
app.post('/api/auth/register-user', authenticateMSP, (req, res) => {
    if (req.user.role !== 'Supervisor') {
        return res.status(403).json({ error: 'Only a Supervisor (SupervisoryMSP) can enroll new MSP officers.' });
    }
    const { username, password, fullName, badgeNumber, role, department } = req.body;
    const ledger = loadLedger();
    if (ledger.users[username]) {
        return res.status(400).json({ error: 'Username already exists in MSP registry.' });
    }

    const mspMap = {
        'First Responder': 'ZambiaPoliceMSP',
        'Forensic Investigator': 'ForensicLabMSP',
        'Supervisor': 'SupervisoryMSP',
        'Judicial Officer': 'JudiciaryMSP'
    };

    ledger.users[username] = {
        username,
        passwordHash: bcrypt.hashSync(password, 10),
        fullName,
        badgeNumber,
        role,
        mspId: mspMap[role] || 'ZambiaPoliceMSP',
        department,
        x509Serial: crypto.randomBytes(7).toString('hex').toUpperCase().match(/.{1,2}/g).join(':')
    };
    saveLedger(ledger);
    res.json({ message: `MSP Identity enrolled for ${fullName} (${role}).` });
});

// STATE API: Get Ledger State, Users & CouchDB Status
app.get('/api/state', authenticateMSP, async (req, res) => {
    const ledger = loadLedger();
    const safeUsers = Object.values(ledger.users).map(({ passwordHash, ...u }) => u);

    let couchOnline = false;
    try {
        const ping = await fetch(COUCHDB_URL);
        couchOnline = ping.ok;
    } catch {
        couchOnline = false;
    }

    res.json({
        channelName: ledger.channelName,
        couchDbOnline: couchOnline,
        users: safeUsers,
        evidenceList: Object.values(ledger.worldState).reverse(),
        blocks: [...ledger.blocks].reverse()
    });
});

// CHAINCODE API 1: Register Digital Evidence + Save to Vault + SHA-256
app.post('/api/evidence/register', authenticateMSP, upload.single('evidenceFile'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Digital evidence file is required.' });

        const { evidenceId, caseNumber, title, category, collectionLocation, description, notes } = req.body;
        const sha256Hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

        // Store file inside Evidence Vault with immutable filename
        const safeName = `${evidenceId.replace(/[^a-zA-Z0-9_-]/g, '_')}_${Date.now()}_${req.file.originalname}`;
        fs.writeFileSync(path.join(VAULT_DIR, safeName), req.file.buffer);

        const ledger = loadLedger();
        const ctx = createFabricContext(ledger, req.user, 'REGISTER_EVIDENCE', evidenceId.trim());

        const record = await chaincode.RegisterEvidence(ctx, {
            evidenceId: evidenceId.trim(),
            caseNumber: caseNumber.trim(),
            title: title.trim(),
            category: category || 'Digital Log / File',
            collectionLocation: collectionLocation.trim(),
            description: description.trim(),
            fileName: req.file.originalname,
            storedFileName: safeName,
            fileSize: `${(req.file.size / 1024).toFixed(2)} KB`,
            mimeType: req.file.mimetype || 'application/octet-stream',
            sha256Hash,
            notes
        });

        res.json({
            message: `Evidence ${record.evidenceId} hashed (SHA-256), vaulted, and committed to Block #${ledger.blocks.length - 1}.`,
            evidence: record
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// CHAINCODE API 2: Transfer Custody
app.post('/api/evidence/transfer', authenticateMSP, async (req, res) => {
    try {
        const { evidenceId, targetUsername, transferReason } = req.body;
        const ledger = loadLedger();
        const recipient = ledger.users[targetUsername];
        if (!recipient) return res.status(404).json({ error: 'Recipient MSP officer not found.' });

        const ctx = createFabricContext(ledger, req.user, 'TRANSFER_CUSTODY', evidenceId);
        const updated = await chaincode.TransferCustody(ctx, evidenceId, recipient, transferReason);

        res.json({
            message: `Chain of Custody for ${evidenceId} transferred to ${recipient.fullName} (${recipient.role}).`,
            evidence: updated
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// CHAINCODE API 3: Log Forensic Analysis / Supervisory Audit / Judicial Ruling
app.post('/api/evidence/event', authenticateMSP, async (req, res) => {
    try {
        const { evidenceId, eventType, findingsReport } = req.body;
        const ledger = loadLedger();
        const ctx = createFabricContext(ledger, req.user, eventType, evidenceId);
        const updated = await chaincode.LogForensicEvent(ctx, evidenceId, eventType, findingsReport);

        res.json({
            message: `Event '${eventType}' recorded on blockchain for ${evidenceId}.`,
            evidence: updated
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// VERIFICATION API 4: Verify Uploaded File Against On-Chain SHA-256
app.post('/api/evidence/verify-file', authenticateMSP, upload.single('verifyFile'), (req, res) => {
    try {
        const { evidenceId } = req.body;
        if (!req.file) return res.status(400).json({ error: 'Please upload a file to verify.' });

        const ledger = loadLedger();
        const evidence = ledger.worldState[evidenceId];
        if (!evidence) return res.status(404).json({ error: `Evidence ${evidenceId} not found.` });

        const liveHash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
        const isAuthentic = liveHash === evidence.sha256Hash;

        res.json({
            evidence,
            testedFileName: req.file.originalname,
            testedFileSize: `${(req.file.size / 1024).toFixed(2)} KB`,
            onChainHash: evidence.sha256Hash,
            computedHash: liveHash,
            isAuthentic,
            verifiedBy: `${req.user.fullName} (${req.user.role} - ${req.user.mspId})`,
            badgeNumber: req.user.badgeNumber,
            verifiedAt: new Date().toISOString()
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// VERIFICATION API 5: Full Cryptographic Blockchain Audit
app.get('/api/ledger/audit', authenticateMSP, (req, res) => {
    const ledger = loadLedger();
    const blocks = ledger.blocks;
    const discrepancies = [];

    for (let i = 1; i < blocks.length; i++) {
        const curr = blocks[i];
        const prev = blocks[i - 1];

        if (curr.previousBlockHash !== prev.blockHash) {
            discrepancies.push(`Block #${curr.blockNumber}: previousBlockHash mismatch.`);
        }
        const expectedHeader = `${curr.blockNumber}|${curr.previousBlockHash}|${curr.dataHash}|${curr.txId}|${curr.timestamp}`;
        const recalculatedHash = crypto.createHash('sha256').update(expectedHeader).digest('hex');
        if (recalculatedHash !== curr.blockHash) {
            discrepancies.push(`Block #${curr.blockNumber}: block hash tampering detected.`);
        }
    }

    res.json({
        valid: discrepancies.length === 0,
        totalBlocksVerified: blocks.length,
        discrepancies,
        auditedAt: new Date().toISOString(),
        auditedBy: `${req.user.fullName} (${req.user.mspId})`
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`\n========================================================================`);
    console.log(`🔗 ZUT HYPERLEDGER FABRIC DIGITAL EVIDENCE SYSTEM (WORKING EDITION)`);
    console.log(`🌐 Application URL: http://localhost:${PORT}`);
    console.log(`🗄️  CouchDB Fauxton UI (if Docker running): http://localhost:5984/_utils`);
    console.log(`========================================================================\n`);
});
'use strict';

/**
 * Hyperledger Fabric Smart Contract (Chaincode)
 * System: Blockchain-Based Chain of Custody Tracking System for Digital Evidence
 * Author: Kandela Luwi (Zambia University College of Technology)
 */

class EvidenceChaincode {

    _requireRole(clientIdentity, allowedRoles) {
        if (!allowedRoles.includes(clientIdentity.role)) {
            throw new Error(
                `MSP Authorization Failed: Role '${clientIdentity.role}' (${clientIdentity.mspId}) cannot execute this transaction. Authorized roles: ${allowedRoles.join(', ')}`
            );
        }
    }

    /**
     * Register new digital evidence with SHA-256 fingerprint
     */
    async RegisterEvidence(ctx, evidencePayload) {
        this._requireRole(ctx.clientIdentity, ['First Responder', 'Forensic Investigator']);

        const existing = await ctx.stub.getState(evidencePayload.evidenceId);
        if (existing && existing.length > 0) {
            throw new Error(`Evidence ID '${evidencePayload.evidenceId}' is already registered on the ledger.`);
        }

        const timestamp = new Date().toISOString();
        const record = {
            _id: evidencePayload.evidenceId,
            docType: 'digitalEvidence',
            evidenceId: evidencePayload.evidenceId,
            caseNumber: evidencePayload.caseNumber,
            title: evidencePayload.title,
            category: evidencePayload.category,
            collectionLocation: evidencePayload.collectionLocation,
            description: evidencePayload.description,
            fileName: evidencePayload.fileName,
            storedFileName: evidencePayload.storedFileName,
            fileSize: evidencePayload.fileSize,
            mimeType: evidencePayload.mimeType,
            sha256Hash: evidencePayload.sha256Hash,
            status: 'REGISTERED_IN_CUSTODY',
            currentCustodianId: ctx.clientIdentity.username,
            currentCustodianName: ctx.clientIdentity.fullName,
            currentCustodianRole: ctx.clientIdentity.role,
            currentCustodianMsp: ctx.clientIdentity.mspId,
            createdAt: timestamp,
            custodyHistory: [
                {
                    step: 1,
                    txId: ctx.stub.getTxID(),
                    action: 'EVIDENCE_COLLECTED_AND_REGISTERED',
                    actorUsername: ctx.clientIdentity.username,
                    actorName: ctx.clientIdentity.fullName,
                    actorRole: ctx.clientIdentity.role,
                    mspId: ctx.clientIdentity.mspId,
                    fromCustodian: `INITIAL_COLLECTION (${evidencePayload.collectionLocation})`,
                    toCustodian: `${ctx.clientIdentity.fullName} [${ctx.clientIdentity.role}]`,
                    notes: evidencePayload.notes || 'Digital evidence acquired, hashed via SHA-256, and sealed on blockchain.',
                    verifiedHash: evidencePayload.sha256Hash,
                    timestamp: timestamp
                }
            ]
        };

        await ctx.stub.putState(record.evidenceId, Buffer.from(JSON.stringify(record)));
        return record;
    }

    /**
     * Transfer custody — enforces that only the current custodian or a Supervisor can transfer
     */
    async TransferCustody(ctx, evidenceId, recipientProfile, transferReason) {
        this._requireRole(ctx.clientIdentity, ['First Responder', 'Forensic Investigator', 'Supervisor']);

        const bytes = await ctx.stub.getState(evidenceId);
        if (!bytes || bytes.length === 0) {
            throw new Error(`Evidence ID '${evidenceId}' not found on ledger.`);
        }

        const evidence = JSON.parse(bytes.toString());

        // Enforce strict custody ownership check
        const isCurrentCustodian = evidence.currentCustodianId === ctx.clientIdentity.username;
        const isSupervisor = ctx.clientIdentity.role === 'Supervisor';
        if (!isCurrentCustodian && !isSupervisor) {
            throw new Error(
                `Custody Violation: Only the current custodian (${evidence.currentCustodianName}) or an authorized Supervisor can transfer this evidence.`
            );
        }

        if (evidence.currentCustodianId === recipientProfile.username) {
            throw new Error(`Recipient (${recipientProfile.fullName}) is already the current custodian of ${evidenceId}.`);
        }

        const previousHolder = `${evidence.currentCustodianName} [${evidence.currentCustodianRole}]`;
        const newHolder = `${recipientProfile.fullName} [${recipientProfile.role}]`;
        const timestamp = new Date().toISOString();

        evidence.currentCustodianId = recipientProfile.username;
        evidence.currentCustodianName = recipientProfile.fullName;
        evidence.currentCustodianRole = recipientProfile.role;
        evidence.currentCustodianMsp = recipientProfile.mspId;
        evidence.status = `TRANSFERRED_TO_${recipientProfile.role.toUpperCase().replace(/\s+/g, '_')}`;

        evidence.custodyHistory.push({
            step: evidence.custodyHistory.length + 1,
            txId: ctx.stub.getTxID(),
            action: 'CUSTODY_TRANSFER',
            actorUsername: ctx.clientIdentity.username,
            actorName: ctx.clientIdentity.fullName,
            actorRole: ctx.clientIdentity.role,
            mspId: ctx.clientIdentity.mspId,
            fromCustodian: previousHolder,
            toCustodian: newHolder,
            notes: transferReason,
            verifiedHash: evidence.sha256Hash,
            timestamp: timestamp
        });

        await ctx.stub.putState(evidenceId, Buffer.from(JSON.stringify(evidence)));
        return evidence;
    }

    /**
     * Log Forensic Examination, Supervisory Audit, or Judicial Admissibility Ruling
     */
    async LogForensicEvent(ctx, evidenceId, eventType, findingsReport) {
        this._requireRole(ctx.clientIdentity, ['Forensic Investigator', 'Supervisor', 'Judicial Officer']);

        const bytes = await ctx.stub.getState(evidenceId);
        if (!bytes || bytes.length === 0) {
            throw new Error(`Evidence ID '${evidenceId}' not found on ledger.`);
        }

        const evidence = JSON.parse(bytes.toString());
        const timestamp = new Date().toISOString();

        evidence.status = eventType;
        evidence.custodyHistory.push({
            step: evidence.custodyHistory.length + 1,
            txId: ctx.stub.getTxID(),
            action: eventType,
            actorUsername: ctx.clientIdentity.username,
            actorName: ctx.clientIdentity.fullName,
            actorRole: ctx.clientIdentity.role,
            mspId: ctx.clientIdentity.mspId,
            fromCustodian: `${evidence.currentCustodianName} [${evidence.currentCustodianRole}]`,
            toCustodian: `${evidence.currentCustodianName} [${evidence.currentCustodianRole}]`,
            notes: findingsReport,
            verifiedHash: evidence.sha256Hash,
            timestamp: timestamp
        });

        await ctx.stub.putState(evidenceId, Buffer.from(JSON.stringify(evidence)));
        return evidence;
    }
}

module.exports = EvidenceChaincode;
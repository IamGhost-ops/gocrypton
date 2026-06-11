package main

import (
        "crypto/ed25519"
        "crypto/rand"
        "crypto/sha256"
        "encoding/hex"
        "fmt"
        "log"
        "time"
        

)


type AuditLogBlock struct {
        Index        int    `json:"index"`
        Timestamp    string `json:"timestamp"`
        TetragonData string `json:"tetragon_data"`
        PrevHash     string `json:"prev_hash"`
        CurrentHash  string `json:"current_hash"`
        Ed25519Sig   string `json:"ed25519_signature_hex"`

}


func calculateSHA256(data string) string {
        hash := sha256.New()
        hash.Write([]byte(data))
        return hex.EncodeToString(hash.Sum(nil))

}

func main() {
        fmt.Println("[Ed25519-Signer] Initializing Ed25519 log signer for Tetragon v1.7.0...")

        pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
                log.Fatalf("Failed to generated Ed25519 keys: %v", err)
        }
        fmt.Println("[Ed25519] Generated Ed25519 key pair.")

        genesisHash := calculateSHA256("GENESIS_BOOT_STATE")

        rawTetragonEvent := `{"process":{"binary":"/bin/cat","pid":4120,"fd_install":3},"action":"SIGKILL","lsm_hook":"bprm_check_security","message":"Unauthorized private key access attempt"}`
        fmt.Printf("\n[SHA-256] Wykryto krytyczne zdarzenie LSM:\n%s\n", rawTetragonEvent)

        signatureBytes := ed25519.Sign(privKey, []byte(rawTetragonEvent))
        pqcSignatureHex := hex.EncodeToString(signatureBytes)

        blockIndex := 1
        blockDataToHash := fmt.Sprintf("%d%s%s%s", blockIndex, rawTetragonEvent, genesisHash, pqcSignatureHex)
        currentHash := calculateSHA256(blockDataToHash)

        newBlock := AuditLogBlock{
                Index:        blockIndex,
                Timestamp:    time.Now().Format(time.RFC3339),
                TetragonData: rawTetragonEvent,
                PrevHash:     genesisHash,
                Ed25519Sig:   ed25519Signature,
                CurrentHash:  currentHash,
}

        fmt.Println("[Ed25519] Log successfully processed and signed by Ed25519 signer.")

        fmt.Println("\n[AUDITOR] Lauching system log integrity verification...")

        decodeSig, err := hex.DecodeString(newBlock.Ed25519Sig)
        if err != nil {
                log.Fatalf("Signature hex decode error: %v", err)
}

        isSignatureValid := ed25519.Verify(pubKey, []byte(newBlock.TetragonData), decodeSig)

        recalculatedData := fmt.Sprintf("%d%s%s%s", newBlock.Index, newBlock.TetragonData, newBlock.PrevHash, newBlock.Ed25519Sig)
        recalculatedHash := calculateSHA256(recalculatedData)
        isChainValid := recalculatedHash == newBlock.CurrentHash

        if isSignatureValid && isChainValid {
                fmt.Println("[SUCCESS] Log is 100% authentic! Ed 25519 signature is valid, chain integrity preserved. No signs of tampering.")
        } else {
                fmt.Println("[ALARM] Tampering detected in audit logs! Cryptographic integrity has been compromised.")
        }


}

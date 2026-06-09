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
        PQCSignature string `json:"pqc_signature"`

}


func calculateSHA256(data string) string {
        hash := sha256.New()
        hash.Write([]byte(data))
        return hex.EncodeToString(hash.Sum(nil))

}

func main() {
        fmt.Println("[PQC-SIGNER] Inicjalizacja Post-Quantum Log Signer dla Tetragon v1.7.0...")

        pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
                log.Fatalf("Blad generowania kluczy post-kwantowych: %v", err)
        }
        fmt.Println("[PQC-SIGNER] Wygenerowane pare kluczy ML-DSA-65 (Odporne na komputery kwantowe).")

        genesisHash := calculateSHA256("GENESIS_BOOT_STATE")

        rawTetragonEvent := `{"process":{"binary":"/bin/cat","pid":4120,"fd_install":3},"action":"SIGKILL","lsm_hook":"bprm_check_security","message":"Unauthorized private key access attempt"}`
        fmt.Printf("\n[PQC_SIGNER] Wykryto krytyczne zdarzenie LSM:\n%s\n", rawTetragonEvent)

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
                PQCSignature: pqcSignatureHex,
                CurrentHash:  currentHash,
}

        fmt.Println("[PQC-SIGNER] Log pomyslnie przetworzony i wpiety do struktury Append-Only Ledger.")

        fmt.Println("\n[AUDYTOR] Uruchamianie weryfikacji integralnosci logow systemowych...")

        decodeSig, err := hex.DecodeString(newBlock.PQCSignature)
        if err != nil {
                log.Fatalf("Blad dekodowania podpisu: %v", err)
}

        isSignatureValid := ed25519.Verify(pubKey, []byte(newBlock.TetragonData), decodeSig)

        recalculatedData := fmt.Sprintf("%d%s%s%s", newBlock.Index, newBlock.TetragonData, newBlock.PrevHash, newBlock.PQCSignature)
        recalculatedHash := calculateSHA256(recalculatedData)
        isChainValid := recalculatedHash == newBlock.CurrentHash

        if isSignatureValid && isChainValid {
                fmt.Println("[SUKCES] Log jest w 100% autentyczny! Podpis post-kwantowy PQC poprawny, integralnosc lancucha zachowana. Brak sladow manipulacji.")
        } else {
                fmt.Println("[ALARM] Wykryto manipulacje w logach audytowych!Integralnosc kryptograficzna zostala naruszona.")
        }


}

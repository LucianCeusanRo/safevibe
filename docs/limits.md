# Limits and non-claims / Limite și ce nu pretindem

This page is part of the product. Read it before you point an editor or a model at SafeVibe.

---

## English

1. **Pseudonymization is not encryption, and it is not end-to-end encryption.** If the backend is a cloud LLM, a transformed prompt still leaves the machine. The provider can store it, be breached, or infer sensitive context from what remains (file structure, error messages, architecture, comments). Calling this “E2E encryption” would be false.

2. **Detectors miss things.** Novel token formats, secrets without known prefixes, screenshots, diagrams, compiled binaries, pre-encoded blobs, and paraphrased personal data will leak. Romanian free-text names and addresses are weaker than CNP checksums. A custom organisation dictionary helps only for what someone remembered to add.

3. **Placeholders leak structure.** A prompt that still says “restart `{{HOST_01}}` in VLAN 34, ticket `{{TICKET_01}}`” tells a model (and a provider log) a lot. Redaction reduces exposure; it does not anonymize an operational incident.

4. **The vault is a high-value file.** Anyone who can read the vault or dump the proxy process can undo the redaction. It stays in the process by default. An optional encrypted export exists; it must never be committed or synced to a shared folder.

5. **Restoration can be wrong.** If the model invents a placeholder SafeVibe does not know, v1 replaces it with `[UNMAPPED_PLACEHOLDER]` rather than guessing a value.

6. **Classified information and many “secrete de serviciu” must not go to a commercial model at all**, even redacted. CERT-EU recommends that only TLP:CLEAR data belongs in commercial LLM prompts. This tool will not make a classified system “safe for Copilot.”

7. **Static scanners are not malware oracles.** A `safe` verdict means “no known static pattern fired,” not “this is harmless.” Delayed payloads and novel obfuscation will be missed. The scanner never executes the target.

8. **Sandboxes escape and AI-generated code can be hostile.** `docker --network none` is a strong default, not a formal isolation proof. v1 will not execute snippets on the host.

9. **No certification claim.** SafeVibe is not an AI Act conformity assessment, a GDPR certification, a DNSC or ADR endorsement, or an accredited tool for classified systems. Do not put logos or wording that imply otherwise.

10. **Legal responsibility stays with the institution and the human who clicks send.** This is a control, like a seatbelt, not a transfer of liability.

---

## Română

1. **Pseudonimizarea nu este criptare și nu este criptare end-to-end.** Dacă backend-ul este un model în cloud, un prompt transformat tot părăsește mașina. Furnizorul îl poate stoca, poate fi spart, sau poate deduce context sensibil din ce rămâne. A spune că acesta este „E2E encryption” ar fi fals.

2. **Detectorii ratează lucruri.** Formate noi de tokeni, secrete fără prefix cunoscut, capturi de ecran, diagrame, binare, date deja encodate și date personale parafrazate vor scăpa. Numele și adresele în text liber, în română, sunt mai slabe decât un CNP cu cifre de control.

3. **Substituenții scurg structură.** Un prompt care încă spune „repornește `{{HOST_01}}` în VLAN 34, tichet `{{TICKET_01}}`” îi spune multe modelului. Redactarea reduce expunerea; nu anonimizează un incident operațional.

4. **Seiful (vault) este un fișier de mare valoare.** Cine poate citi seiful sau procesul proxy poate anula redactarea. Implicit rămâne doar în memorie.

5. **Restaurarea poate greși.** Dacă modelul inventează un substituent necunoscut, v1 îl înlocuiește cu `[UNMAPPED_PLACEHOLDER]`, fără să ghicească o valoare.

6. **Informațiile clasificate și multe secrete de serviciu nu trebuie să ajungă deloc la un model comercial**, nici redactate. Acest instrument nu face un sistem clasificat „sigur pentru Copilot.”

7. **Scanerele statice nu sunt oracole de malware.** Un verdict `safe` / `sigur` înseamnă „nu s-a declanșat niciun tipar cunoscut”, nu „este inofensiv.” Scanerul nu execută ținta.

8. **Sandbox-urile pot fi ocolite, iar codul generat de AI poate fi ostil.** `docker --network none` este un default solid, nu o dovadă formală de izolare. v1 nu execută snippet-uri pe gazdă.

9. **Nicio pretenție de certificare.** SafeVibe nu este o evaluare de conformitate AI Act, o certificare GDPR, o aprobare DNSC sau ADR, și nu este un instrument acreditat pentru sisteme clasificate.

10. **Răspunderea rămâne la instituție și la omul care apasă trimite.** Este un control, ca o centură de siguranță, nu un transfer de răspundere.

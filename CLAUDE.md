---
title: Working contract
status: obowiązujący
last-reviewed: 2026-08-30
owner: Gh0s777tt
---

# CLAUDE.md — kontrakt pracy w `eos-control`

To jest **kontrakt, nie poradnik**. Reguły w §3 są twarde.

Pełny kontrakt ekosystemu jest w repozytorium orkiestrującym:
<https://gitlab.com/e-os/e-os/-/blob/main/CLAUDE.md>. Ten plik zawiera wyłącznie to, co dotyczy
tego repozytorium — reszta obowiązuje bez powtarzania.

## 1. Czym jest to repozytorium

Komponent **typu A** — kod własny E-OS, pełne standardy projektu. E-OS to dystrybucja Redox OS
z dołożonym łańcuchem zaufania; ten katalog nie jest osobnym produktem.

Rozwój i CI na **GitLabie**; GitHub jest lustrem tylko do odczytu i **nie ma automatycznej
synchronizacji** — push wymaga dwóch poleceń.

## 2. Polecenia — zweryfikowane 2026-08-30

```bash
cargo check --no-default-features                    # połowa hosta (bez GUI)
cargo clippy --no-default-features -- -D warnings
cargo test                                            # UWAGA: 0 testów, patrz §4
```

Część graficzna kompiluje się na cel `*-unknown-redox` i **nie zbuduje się na hoście** — Slint
z backendem winit nie kompiluje się nowoczesnym rustc hosta. Buduje ją receptura cookbooka
w repozytorium orkiestrującym.

Żeby zobaczyć zmianę na działającym systemie: podbij przypiętą rewizję tego repozytorium
w `repos.toml` orkiestratora i przebuduj obraz.

## 3. Protokół weryfikacji — reguły twarde

1. **Każda zmiana ma testy.** Jeśli testu napisać się nie da — napisz dlaczego i uzyskaj zgodę
   **przed** złożeniem zmiany.
2. **Zmiana jest skończona**, dopiero gdy przechodzą: `cargo check`, `cargo clippy -D warnings`,
   `cargo test`, a artefakt został **uruchomiony**, nie przemyślany.
3. **Weryfikuj artefakt, nie kod wyjścia.** Do opisu MR-a wklejasz prawdziwe wyjście polecenia.
4. **Bramka sprawdzająca obecność nie jest bramką** — każda kontrola musi mieć test negatywny.
5. **Zmiany dotykające uprawnień** — a w tym repozytorium dotyczy to każdej ścieżki wołającej
   uprzywilejowany shim — wymagają **pisemnej analizy ryzyka i planu wycofania** w opisie MR-a.
6. **Bez commitów na `main`. Bez `force-push`. Bez sekretów. Bez niezwiązanych zmian w jednym MR.**
7. **Pliki generowane regeneruj**, nie poprawiaj ręcznie (`Cargo.lock`).
8. **Dokumentację aktualizuj w tym samym MR** co zmianę, którą opisuje.

## 4. Stan faktyczny, który trzeba znać

**To repozytorium ma zero testów.** Nie jest to niedopatrzenie do przemilczenia — jest zapisane
w `SECURITY.md` i w roadmapie jako `S-13`. Pierwsza zmiana dokładająca testy jest mile widziana
i nie wymaga zgody.

## 5. Definicja ukończenia

- [ ] `cargo check --no-default-features` przechodzi
- [ ] `cargo clippy --no-default-features -- -D warnings` bez ostrzeżeń
- [ ] Testy dodane albo zaktualizowane (albo uzasadniony brak, za zgodą)
- [ ] Prawdziwe wyjście poleceń w opisie MR-a
- [ ] `CHANGELOG.md` ma wpis z odniesieniem do commita
- [ ] Commit podpisany, Conventional Commits, jedna zmiana logiczna
- [ ] Przy zmianach uprawnień — analiza ryzyka i plan wycofania

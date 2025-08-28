# net-syringe
Proof-of-Concept server-assisted DLL manual mapping written in Rust

## Features
- [x] Server-assisted DLL mapping
- [x] Image relocation
- [x] Basic import resolving
- [x] Security cookie initialization
- [x] Erase PE headers
- [x] Execution via `WH_GETMESSAGE` hook
- [x] **Extensible:** `ProcessTrait` interface to implement your own process operations (read, write, allocate memory, etc.)
- [ ] Exception support
- [ ] TLS support
- [ ] 32-bit support

## How it works
1. **Client prepares the target process:** allocates memory for the DLL and resolves the addresses of required imports in the target process.
2. **Server prepares the DLL image:** receives the DLL’s allocation base, performs relocation, resolves imports, applies security cookie, erases PE headers, and returns a fully initialized image.
3. **Client writes and executes the DLL:** writes the prepared image into the allocated memory and calls its entry point (e.g., via `WH_GETMESSAGE` hook).

## Usage
1. Build the project:
```sh
git clone https://github.com/eliasmoflag/net-syringe.git
cd net-syringe
```
2. Start the server:
```sh
cd service
cargo run
```
3. Inject a DLL:
```sh
cd client
cargo run -- --process Notepad.exe --library test.dll --window-class Notepad
```

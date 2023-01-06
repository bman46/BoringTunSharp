# BoringTunSharp
A C# library for Cloudflare's [BoringTun](https://github.com/cloudflare/boringtun).
Note that this library does not create any network interfaces to intercept packets.

## Getting Started
1. Clone this repository or include the NuGet library in your project.
2. Build the BoringTun DLLs for your associated platform and distribute them within your app accordingly.
3. Take a look at the [example](https://github.com/bman46/BoringTunSharp/tree/main/BoringTunTest) for API usage.

## Generate BoringTun DLL
Clone the boringtun git repo and build the library with the following command: `cargo build --lib --no-default-features --release --features ffi-bindings`. Copy the resulting DLL/SO/DYLIB to the root directory of this project.

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. BoringTunSharp is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>

# LEGO SmartAssist IL2CPP Dump — API Summary

Extracted via Il2CppDumper v6.7.46 from `com.lego.smartassist` (APKPure, March 2026).

## Backend Services ("Bilbo")

### Base URLs

| Service | URL |
|---|---|
| P11 Firmware | `https://p11.bilbo.lego.com` |
| AUP (Updates) | `https://aup.bilbo.lego.com` |
| ACT (Telemetry) | `https://act.bilbo.lego.com` |
| External Topics | `https://external.bilbo.lego.com` |
| Dev instance | `https://act.bilbo.lego.dev` |

### Firmware Update Flow (CloudService)

```
CloudService.GetStateFor(product: FWImageProductName, version: Version)
  → GET {P11BilboBaseUrl}/update/{fw_product_name}/state?version={version}
  ← returns: state hash string

CloudService.GetUpdateFor(currentState: string)
  → GET {AupBaseUrl}/update/{current_state}/download
  ← returns: byte[] (firmware binary, ~P11 container)

CloudService.Probe(currentState: string)
  → checks if update is available

CloudService.GetUpdateState(product, version)
  → full update state with version info

CloudService.IsUpdateAvailable(product, version)
  → boolean check
```

Beta channel: `{BaseUrl}/update/beta/{fw_product_name}/state`

### API Authentication

Uses `x-api-key` header. Key is likely embedded in the app configuration or obtained via session.

### AUP (Application Update Platform) API

| Endpoint | Purpose |
|---|---|
| `AupPublicApi.ProbeForUpdate` | Check for firmware update |
| `AupPublicApi.ProbeForUpdateBeta` | Check beta channel |
| `AupPublicApi.DownloadUpdate` | Download firmware by state |
| `AupQaApi.Products` | List products |
| `AupQaApi.Releases` | List releases |
| `AupQaApi.ReleaseInfo` | Release details |
| `AupQaApi.DownloadBundle` | Download full bundle |
| `AupQaApi.Channels` | Release channels |

### Other APIs

| API | Purpose |
|---|---|
| `ActPublicApi.UploadTelemetryDataDirectly` | Upload brick telemetry |
| `ActPublicApi.ReadTelemetryData` | Read telemetry |
| `EnigmaQaApi.CreateSpkitBundle` | SPKIT crypto bundle creation |
| `EnigmaQaApi.Sign` | Cryptographic signing |
| `EnigmaQaApi.SharedKey` | Shared key exchange |
| `PlaykitPublicApi.CompileInputFile` | Compile play scripts |
| `PlaykitPublicApi.GetSupportedVersion` | Script compiler version |
| `RangoQaApi.*` | Element range/claim management |

## BLE Protocol (WDX)

### FirmwareUpdateService

Wraps `IWdxProtocolProcessor` for firmware upload over BLE.

| Method | Purpose |
|---|---|
| `UploadFirmwareAsync(byte[])` | Upload firmware bytes to brick |
| `GetUpdateState()` | Read register 0x88 |
| `GetUpgradeState()` | Read register 0x85 |
| `GetPipelineStage()` | Read register 0x89 |
| `GetBatteryLevel()` | Read register 0x20 |
| `GetChargingState()` | Read register 0x93 |
| `SetUXSignal(short)` | Write register 0x90 |
| `SetTravelMode()` | Write register 0x96 |
| `RebootAndConfigureOverTheAirFirmwareAsync()` | Reboot for OTA |

### Key Enums

```csharp
enum UpgradeState { Ready = 0, InProgress = 1, LowBattery = 2 }
enum FWImageProductName { AudioBrick, PanelCharger }
```

## Key Namespaces

| Namespace | Contents |
|---|---|
| `Horizon.Services.Cloud` | CloudService, CloudWebRequest |
| `HubFeatureLibrary.HubServices.ConcreteServices.FirmwareUpdate` | FirmwareUpdateService |
| `LEGO.ConnectKit` | BLE connectivity |
| `BilboAPI` | Backend API client (15,175 types) |

## Notable Findings

- The "Bilbo" backend is LEGO's internal platform for device management
- `FWImageProductName` enum confirms AudioBrick and PanelCharger as the two product types
- The `EnigmaQaApi` handles cryptographic operations (signing, shared keys, SPKIT bundles)
- `PlaykitPublicApi.CompileInputFile` suggests play scripts can be compiled server-side
- `AupQaApi` endpoints exist for QA/staging firmware management
- User-Agent: `OpenAPI-Generator/1.0.0/csharp` — the Bilbo API client is auto-generated from an OpenAPI spec

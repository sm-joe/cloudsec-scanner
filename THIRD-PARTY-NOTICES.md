# Third-party notices

CloudSec Scanner is distributed under Apache-2.0. The repository includes unmodified validation schema snapshots; their origin and blob IDs are documented in schemas/README.md.

- SchemaStore (https://github.com/SchemaStore/schemastore): SARIF schema snapshot, distributed by SchemaStore under its Apache-2.0 repository license. The underlying SARIF specification is an OASIS standard; see schemas/OASIS-LICENSE.md for the upstream OASIS repository terms. This does not claim ownership of or relicense the standard.
- OWASP CycloneDX specification (https://github.com/CycloneDX/specification): CycloneDX 1.6 schema under Apache-2.0. The accompanying SPDX identifier enumeration is from the specification repository. JSON Signature Format schema was developed by Anders Rundgren and is published under Apache-2.0.
- Python dependencies are separately licensed by their respective authors. They are installed as dependencies, not bundled in the CloudSec wheel. See the runtime SBOM for the installed candidate inventory.

See LICENSE for the Apache-2.0 text. Original schema content remains unchanged.

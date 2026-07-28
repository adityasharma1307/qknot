# Entropy samples

The bytes analysed in [`../../docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md)
section 5, committed so the analysis can be re-run over the same input.

| file | source | bytes | re-fetchable by a third party? |
|---|---|---|---|
| `anu_*.bin` | ANU Quantum Random Numbers, keyed API | 125,000 | **no** |
| `beacon_*.bin` | NIST Randomness Beacon, chain 2 | 125,000 | **yes** |
| `system_*.bin` | `os.urandom` on the recording machine | 125,000 | no (nor should it be) |

Each `.bin` has a `.json` manifest with a SHA-256 of the sample, the collection
window, and the request count. The beacon manifest additionally records every
pulse index and `output_value`, which is what makes that row of the table a
"yes": anyone can re-request those pulses from NIST and confirm the sample was
not fabricated.

**No API key appears in any manifest.** The ANU key is read from `ANU_API_KEY`
or `--anu-key` and never written to disk. If you re-collect, keep it that way.

## These are samples, not a source of randomness

Nothing in `qresp` reads these files. They exist to be analysed, and they are
public, recorded, and years old by the time anyone reads this. Using them as
key material would be catastrophic and is the reason this paragraph exists.

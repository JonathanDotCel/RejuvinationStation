# Rejuvination Station

Quick n dirty cross platform app to patch in missing/broken ECC/EDC on disk images.

Skips sectors 162, 163, 164, 165 (license data), so works for PSX disks.
.NETCore so should work fine on Linux/Mac

Useful for e.g. homebrew where the error correction/detection codes might never have been generated.
Normally that'd be fixed by just burning the .bin to a physical disk, but that's not great if you want to e.g. use the xStation.

The meat & bones of the code is lifted from the PCSX project - see the license in the header for credits!

Reqs:
.NET core 3.1
(Will be less fuss with VS2019, VS2022, etc)
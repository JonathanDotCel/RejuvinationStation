/***************************************************************************
 *   Copyright (C) 2007 PCSX-df Team                                       *
 *   Copyright (C) 2009 Wei Mingzhi                                        *
 *   Copyright (C) 2012 notaz                                              *
 *   Copyright (C) 2002-2011 Neill Corlett                                 *
 *   Copyright (C) 2022 Sickle?                                            *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

// Don't attempt to "fix" the PSX license stuff
// in sectors 162, 163, 164, 165
#define PSX_MODE

//
// Credit:
// A good chunk of the logic has been ganked from the PCSX project:
// https://github.com/grumpycoders/pcsx-redux/blob/main/src/core/cdriso.cc#L112-L264
// 
// References
// https://www.ecma-international.org/publications/files/ECMA-ST/Ecma-168.pdf P114
// https://www.ecma-international.org/publications/files/ECMA-ST/Ecma-130.pdf
// https://www.gnu.org/software/libcdio/libcdio.html
//

using System;
using System.IO;

class Program
{

    const int RAWSECTOR = 2352;

    public enum DiscType { META, MODE1, MODE2FORM1, MODE2FORM2 };

    // The expected sync pattern at the start of a sector
    static byte[] syncPattern = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

    static int Main(string[] args)
    {

        if (args.Length != 2)
        {
            Console.WriteLine("usage: RejuvinationStation <input file> <outputfile>");
            return 1;
        }

        byte[] inFile;

        Console.WriteLine("Loading into ram...");

        try
        {
            inFile = File.ReadAllBytes(args[0]);
        }
        catch (Exception e)
        {
            Console.WriteLine("ohfuck.avi, we hit a problem:\n" + e);
            return 1;
        }

        if (inFile.Length % RAWSECTOR != 0)
        {
            Console.WriteLine("warning, filesize is not a multiple of 2352...");
        }

        BuildLUTs();

        int numChanges = 0;

        for (int offset = 0; offset < inFile.Length; offset += RAWSECTOR)
        {
            if (CheckSector(inFile, offset))
            {
                numChanges++;
            }
        }

        if (numChanges == 0)
        {
            Console.WriteLine("Warning: no bytes changed. (Writing anyway)");
        }
        else
        {
            Console.WriteLine($"Changes made: {numChanges}");
        }

        // We should write it anyway, incase something's being batched
        // and relies on the output being present

        try
        {
            File.WriteAllBytes(args[1], inFile);
        }
        catch (System.Exception e)
        {
            Console.WriteLine("Exception writing the changes to disk!\n" + e);
            return 1;
        }

        Console.WriteLine("Saved to " + args[1]);

        return 0;

    }

    // Returns: 
    static bool CheckSector(byte[] inBytes, int inOffset)
    {

        int offset = inOffset;
        int lba = (inOffset / RAWSECTOR) + 150;

        // https://i.imgur.com/kQRqeBg.png


#if PSX_MODE
        // Don't trash the license stuff on the PS1
        if (lba >= 162 && lba <= 165)
        {
            return false;
        }
#endif

        // bytes 0-11: sync bytes
        if (!CompareSequence(offset, inBytes, syncPattern))
        {
            Console.WriteLine("no sync pattern on " + lba);
            return false;
        }
        offset += 12;

        // bytes 12, 13, 14: sector address in MSF format.
        byte m = inBytes[offset++];
        byte s = inBytes[offset++];
        byte f = inBytes[offset++];

        UInt32 expectedLBA = LBAFromMSF(m, s, f);
        if (lba != expectedLBA)
        {
            Console.WriteLine("MFS doesn't match LBA @ " + lba + " vs " + expectedLBA);
            return false;
        }

        // byte 15 = mode
        byte mode = inBytes[offset++];
        if (mode != 2)
        {
            Console.WriteLine("Not a mode2 sector @ " + lba);
            return false;
        }

        // bytes 16-23 = subheader A & B
        byte[] subHeaderA = ReadBytes(offset, inBytes, 4);
        offset += 4;
        byte[] subHeaderB = ReadBytes(offset, inBytes, 4);
        offset += 4;

        if (!CompareSequence(0, subHeaderA, subHeaderB))
        {
            Console.WriteLine("Subheader mismatch @ " + lba + " (" + subHeaderA[2] + " vs " + subHeaderB[2] + " )");
            //return false;
        }

        // grab the form bit from subheader[2]
        int form = ((subHeaderA[2] & 0x20) != 0) ? 2 : 1;
        int len = (form == 2) ? 2324 : 2048;

        UInt32 edc = 0;

        // recompute the EDC bytes starting with the subheader
        for (int i = 0; i < 4; i++)
        {
            edc = edcLut[(edc ^ subHeaderA[i]) & 0xff] ^ (edc >> 8);
        }
        for (int i = 0; i < 4; i++)
        {
            edc = edcLut[(edc ^ subHeaderB[i]) & 0xff] ^ (edc >> 8);
        }

        // then we have <len> bytes of funtimes
        for (int i = 0; i < len; i++)
        {
            edc = edcLut[(edc ^ inBytes[offset + i]) & 0xff] ^ (edc >> 8);
        }
        offset += len;

        // the 4 bytes after <len> are the EDC bytes
        UInt32 oldEdc = ReadUint32(offset, inBytes);

        bool dirty = false;

        if (oldEdc != edc)
        {
            Console.WriteLine("EDC mismatch at lba " + lba + "! new=" + edc.ToString("X") + " old=" + oldEdc.ToString("X"));
            WriteUint32(offset, inBytes, edc);
            dirty = true;

            if (form == 1)
            {
                // NOTE: takes the offset we passed in, not the current
                FixECC((UInt32)inOffset, inBytes, DiscType.MODE2FORM1);
            }

        }
        offset += 4;

        return dirty;

    }

    static byte FromBCD(byte x) { return (byte)((x & 0x0f) + ((x & 0xf0) >> 4) * 10); }

    // Get the LBA from Mins/Secs/Frames
    static UInt32 LBAFromMSF(byte m, byte s, byte f)
    {
        return (UInt32)(FromBCD(m) * 60 + FromBCD(s)) * 75 + FromBCD(f);
    }

    // Grab 32 bits from a buffer
    static UInt32 ReadUint32(int offset, byte[] source)
    {
        return (UInt32)(source[offset] | (source[offset + 1] << 8) | (source[offset + 2] << 16) | (source[offset + 3] << 24));
    }

    // Write 32 bits to a buffer
    static void WriteUint32(int offset, byte[] source, UInt32 inValue)
    {
        source[offset] = (byte)(inValue & 0xff);
        source[offset + 1] = (byte)((inValue >> 8) & 0xff);
        source[offset + 2] = (byte)((inValue >> 16) & 0xff);
        source[offset + 3] = (byte)((inValue >> 24) & 0xff);
    }

    // Grab a block of bytes from a buffer
    static byte[] ReadBytes(int offset, byte[] source, int length)
    {
        byte[] returnVal = new byte[length];
        Buffer.BlockCopy(source, offset, returnVal, 0, length);
        return returnVal;
    }

    // I'm not sure it needs a comment.
    static bool CompareSequence(int offset, byte[] source, byte[] comp)
    {
        for (int i = 0; i < comp.Length; i++)
        {
            if (source[i + offset] != comp[i]) return false;
        }
        return true;
    }

    // Write ECC block (either P or Q)
    static void FixECC(UInt32 offset, byte[] inBytes, DiscType inType)
    {

        if (inType == DiscType.MODE1)
        {
            WriteSector(offset + 0xC, offset + 0x10, offset + 0x81C, inBytes);
        }
        if (inType == DiscType.MODE2FORM1)
        {
            WriteSector(0, offset + 0x10, offset + 0x81C, inBytes);
        }

    }

    static void WriteSector(UInt32 addrOffset, UInt32 dataOffset, UInt32 eccWriteOffset, byte[] inBytes)
    {

        ECCWritePQ(addrOffset, dataOffset, 86, 24, 2, 86, eccWriteOffset, inBytes);          // P
        ECCWritePQ(addrOffset, dataOffset, 52, 43, 86, 88, eccWriteOffset + 0xAC, inBytes);  // Q

    }

    static void ECCWritePQ(
        UInt32 addrOffset,
        UInt32 dataOffset,
        UInt32 majorCount, UInt32 minorCount,
        UInt32 majorMult, UInt32 minorInc,
        UInt32 eccOffset,
        byte[] inBytes
    )
    {

        byte[] addrBytes = addrOffset == 0 ? new byte[] { 0, 0, 0, 0 } : inBytes;
        byte[] dataBytes = inBytes;
        byte[] eccBytes = inBytes;

        UInt32 size = majorCount * minorCount;

        for (UInt32 major = 0; major < majorCount; major++)
        {
            UInt32 index = (major >> 1) * majorMult + (major & 1);
            byte eccA = 0;
            byte eccB = 0;
            UInt32 minor;
            for (minor = 0; minor < minorCount; minor++)
            {
                byte temp;
                if (index < 4)
                {
                    temp = addrBytes[addrOffset + index];
                }
                else
                {
                    temp = dataBytes[dataOffset + index - 4];
                }
                index += minorInc;
                if (index >= size)
                {
                    index -= size;
                }
                eccA ^= temp;
                eccB ^= temp;
                eccA = eccFLut[eccA];
            }
            eccA = eccBLut[eccFLut[eccA] ^ eccB];
            eccBytes[major + eccOffset] = (eccA);
            eccBytes[major + majorCount + eccOffset] = (byte)(eccA ^ eccB);
        }

    }

    static byte[] eccFLut = new byte[256];
    static byte[] eccBLut = new byte[256];
    static UInt32[] edcLut = new UInt32[256];

    static void BuildLUTs()
    {
        UInt32 i;
        for (i = 0; i < 256; i++)
        {
            UInt32 edc = i;
            UInt32 j = (UInt32)(i << 1) ^ (UInt32)((i & 0x80) != 0 ? 0x11D : 0);
            eccFLut[i] = (byte)j;
            eccBLut[i ^ j] = (byte)i;
            for (j = 0; j < 8; j++)
            {
                edc = (UInt32)(edc >> 1) ^ (UInt32)((edc & 1) != 0 ? 0xD8018001 : 0);
            }
            edcLut[i] = edc;
        }
    }

}


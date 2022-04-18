/*
    MIT License

    Copyright (c) 2022 秦川(Chuan Qin), qc2105@qq.com

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System;
using Tpm2Lib;
using System.Diagnostics;
using System.Text;

namespace ConsoleApp1
{
    internal class Program
    {
        static TpmHandle CreateAppKey(Tpm2 tpm, TpmHandle primHandle, out TpmPublic keyPublic)
        {
            TpmPublic keyInPublic = new TpmPublic(
                TpmAlgId.Sha1,
                ObjectAttr.Decrypt | ObjectAttr.Sign | ObjectAttr.FixedParent | ObjectAttr.FixedTPM
                    | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                null,
                new RsaParms(
                    new SymDefObject(),
                    new NullAsymScheme(),
                    2048, 0),
               new Tpm2bPublicKeyRsa());

            SensitiveCreate sensCreate = new SensitiveCreate(new byte[] { 1, 2, 3 }, null);
          
            TpmPrivate keyPrivate = tpm.Create(primHandle,
                                               sensCreate,
                                               keyInPublic,
                                               null,
                                               new PcrSelection[0],
                                               out keyPublic,
                                               out _,
                                               out _,
                                               out _);

            tpm._Behavior.Strict = true;

            tpm._ExpectError(TpmRc.AuthMissing)
               .Load(primHandle, keyPrivate, keyPublic);

            TpmHandle keyHandle = tpm[Auth.Default].Load(primHandle, keyPrivate, keyPublic);

            Console.WriteLine("App Key created.");

            tpm._Behavior.Strict = false;

            return keyHandle;
        }

        static TpmHandle CreateSRK(Tpm2 tpm)
        {
            var srkTemplate = new TpmPublic(TpmAlgId.Sha256,                    
                                            ObjectAttr.Restricted |           
                                            ObjectAttr.Decrypt |           
                                            ObjectAttr.FixedParent | ObjectAttr.FixedTPM | 
                                            ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                                            null,                               
                                            new RsaParms(new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                                                         new NullAsymScheme(),  
                                                         2048, 0),              
                                            new Tpm2bPublicKeyRsa());


            TpmHandle keyHandle = tpm.CreatePrimary(TpmRh.Owner,           
                                                    new SensitiveCreate(null, null),
                                                    srkTemplate,            
                                                    null,                   
                                                    new PcrSelection[0],    
                                                    out TpmPublic srkPublic,          
                                                    out _,    
                                                    out _,    
                                                    out _);

            Console.WriteLine("SRK Key created.");

            return keyHandle;          
        }

        public static void Initializa(Tpm2 tpm)
        {
            TpmHandle parentKey = CreateSRK(tpm);
            
            MakePersistent(tpm, parentKey, 0x5000);
            TpmHandle keyHandle = CreateAppKey(tpm, parentKey, out _);

            MakePersistent(tpm, keyHandle, 0x5001);
        }

        static TpmHandle MakePersistent(Tpm2 tpm, TpmHandle keyHandle, int handleIndex)
        {
            TpmHandle persistentHandle = TpmHandle.Persistent(handleIndex);

            tpm._AllowErrors()
               .EvictControl(TpmRh.Owner, persistentHandle, persistentHandle);
            if (tpm._LastCommandSucceeded())
            {
                Console.WriteLine("Removed previous persistent Key.");
            }

            tpm.EvictControl(TpmRh.Owner, keyHandle, persistentHandle);
            Console.WriteLine("Key is persistent now.");

            return persistentHandle;
        }

        public static void RsaDecrypt(Tpm2 tpm, TpmHandle rsaKeyHanle, string cipherBase64Text)
        {
            IAsymSchemeUnion decScheme = new SchemeOaep(TpmAlgId.Sha256);
            byte[] keyAuth = new byte[] { 1, 2, 3 };
            Console.WriteLine("============decrypted===================");

            byte[] recovered_encrypted = Convert.FromBase64String(cipherBase64Text);

            Debug.Assert(256 == recovered_encrypted.Length);

            //
            byte[] decrypted = tpm[keyAuth].RsaDecrypt(rsaKeyHanle, recovered_encrypted, decScheme, null);

            string plainText = Encoding.UTF8.GetString(Convert.FromBase64String(Convert.ToBase64String(decrypted)));

            Console.WriteLine(plainText);
            Console.WriteLine("============decrypted ended=============");
        }

        public static string RsaEncrypt(Tpm2 tpm, TpmHandle rsaKeyHanle, string PlainText)
        {
            string base64PlainText = Convert.ToBase64String(Encoding.UTF8.GetBytes(PlainText));
            byte[] message = Convert.FromBase64String(base64PlainText);

            IAsymSchemeUnion decScheme = new SchemeOaep(TpmAlgId.Sha256);
            
            byte[] encrypted = tpm.RsaEncrypt(rsaKeyHanle, message, decScheme, null);

            Console.WriteLine("============encrypted===================");
            string cipherText = Convert.ToBase64String(encrypted);
            Console.WriteLine(cipherText);
            Console.WriteLine("============encrypted ended=============");

            return cipherText;
        }

        static void WriteUsage(string appName)
        {
            Console.WriteLine();
            Console.WriteLine("Usage: " + appName + "[-init/-enc <PlainText>/-dec <cipher_text>]");
        }

        static void Main(string[] args)
        {
            Tpm2Device tpmDevice;
            tpmDevice = new TbsDevice();
            tpmDevice.Connect();
            var tpm = new Tpm2(tpmDevice);

            if (args.Length == 0)
            {
                WriteUsage("ConsoleApp.exe");
                tpm.Dispose();
                return;
            }
            
            if (string.Compare(args[0], "-init", true) == 0)
            {
                Initializa(tpm);
                
                tpm.Dispose();
                return;
            }
            else if (string.Compare(args[0], "-enc", true) == 0 && args.Length == 2)
            {
                TpmHandle rsaHandle = TpmHandle.Persistent(0x5001);
                RsaEncrypt(tpm, rsaHandle, args[1]);
                
                tpm.Dispose();
                return;

            }
            else if (string.Compare(args[0], "-dec", true) == 0 && args.Length == 2)
            {
                TpmHandle rsaHandle = TpmHandle.Persistent(0x5001);
                RsaDecrypt(tpm, rsaHandle, args[1]);
                 
                tpm.Dispose();
                return;
            }
            else
            {
                WriteUsage("ConsoleApp.exe");
            }

            tpm.Dispose();

        }
    }
}

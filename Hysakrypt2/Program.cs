using System;
using System.Collections.Generic;
using System.IO;
using CommandLine;

namespace Hysakrypt2
{
    [Verb("encrypt", HelpText = "Encrypt a file.")]
    class EncryptOptions
    {
        [Option('f', "file", Required = false, HelpText = "The file path to encrypt/decrypt.")]
        public string FilePath { get; set; }
        
        [Option('d', "directory", Required = false, HelpText = "The directory to encrypt/decrypt.")]
        public string Directory { get; set; }
        
        [Option('p', "password", Required = true, HelpText = "The password to use.")]
        public string Password { get; set; }
    }
    
    [Verb("decrypt", HelpText = "Decrypt a file.")]
    class DecryptOptions
    {
        [Option('f', "file", Required = false, HelpText = "The file path to encrypt/decrypt.")]
        public string FilePath { get; set; }
        
        [Option('d', "directory", Required = false, HelpText = "The directory to encrypt/decrypt.")]
        public string Directory { get; set; }
        
        [Option('p', "password", Required = true, HelpText = "The password to use.")]
        public string Password { get; set; }
    }
    
    class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine(@"                                                        ");
            Console.WriteLine(@"                        _                     _   ____  ");
            Console.WriteLine(@"  /\  /\_   _ ___  __ _| | ___ __ _   _ _ __ | |_|___ \ ");
            Console.WriteLine(@" / /_/ / | | / __|/ _` | |/ / '__| | | | '_ \| __| __) |");
            Console.WriteLine(@"/ __  /| |_| \__ \ (_| |   <| |  | |_| | |_) | |_ / __/ ");
            Console.WriteLine(@"\/ /_/  \__, |___/\__,_|_|\_\_|   \__, | .__/ \__|_____|");
            Console.WriteLine(@"        |___/                     |___/|_|              ");
            Console.WriteLine(@"                                                        " + Environment.NewLine);
            
            return Parser.Default.ParseArguments<EncryptOptions, DecryptOptions>(args)
                .MapResult(
                    (EncryptOptions opts) => RunEncrypt(opts),
                    (DecryptOptions opts) => RunDecrypt(opts),
                    errs => 1);
        }

        static int RunEncrypt(EncryptOptions options)
        {
            var hysa = new HysaAes();

            var files = new List<string>();

            if (options.FilePath != null)
            {
                files.Add(options.FilePath);
            } else if (options.Directory != null)
            {
                files.AddRange(GetFiles(options.Directory));
            }
            else
            {
                throw new ArgumentNullException();
            }

            foreach (var file in files)
            {
                var encryptResult = hysa.Encrypt(file, options.Password);
                if (encryptResult != 0)
                {
                    Console.WriteLine($"Failed encrypting {file}");
                }
                else
                {
                    Console.WriteLine($"Encrypted {file}");
                }
            }

            return 0;
        }

        static int RunDecrypt(DecryptOptions options)
        {
            var hysa = new HysaAes();
            
            var files = new List<string>();

            if (options.FilePath != null)
            {
                files.Add(options.FilePath);
            } else if (options.Directory != null)
            {
                files.AddRange(GetFiles(options.Directory));
            }
            else
            {
                throw new ArgumentNullException();
            }

            foreach (var file in files)
            {
                var encryptResult = hysa.Decrypt(file, options.Password);
                if (encryptResult != 0)
                {
                    Console.WriteLine($"Failed decrypting {file}");
                }
                else
                {
                    Console.WriteLine($"Decrypted {file}");
                }
            }

            return 0;
        }
        
        static IEnumerable<string> GetFiles(string path) {
            var queue = new Queue<string>();
            queue.Enqueue(path);
            while (queue.Count > 0)
            {
                path = queue.Dequeue();
                try
                {
                    foreach (var subDir in Directory.GetDirectories(path))
                    {
                        queue.Enqueue(subDir);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex);
                }

                string[] files = null;
                try
                {
                    files = Directory.GetFiles(path);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex);
                }

                if (files != null)
                {
                    for (var i = 0; i < files.Length; i++)
                    {
                        yield return files[i];
                    }
                }
            }
        }
    }
}

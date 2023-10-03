#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates keys of type RSA

"""

from pkcs11_utils import *

def main():
    args = parse_in_rsa_args()
    if args is None:
        return

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    algorithms_RSA_PKCS = ["SHA1-RSA-PKCS","SHA224-RSA-PKCS","SHA256-RSA-PKCS","SHA384-RSA-PKCS","SHA512-RSA-PKCS"]
    algorithms_RSA_PKCS_PSS = ["SHA1-RSA-PKCS-PSS","SHA224-RSA-PKCS-PSS","SHA256-RSA-PKCS-PSS","SHA384-RSA-PKCS-PSS","SHA512-RSA-PKCS-PSS"]

    log.info("Generating RSA keypair: %s" % (args.key_type))
    run("%s --module %s --keypairgen --key-type  %s --label sss:0xEF00000A" % (pkcs11_tool, module_path, args.key_type))
    log.info("###################################################")

    log.info("Retrieving Public Key")
    run("%s --module %s --read-object --type pubkey --label sss:0xEF00000A -o %srsa_%s_0xEF00000A_public.key" % (pkcs11_tool, module_path, output_dir, args.key_type.split(":")[1]))
    log.info("###################################################")


    log.info("Signing data with length 10 bytes with key: %s algo: RSA-PKCS" % (args.key_type))
    run("%s --module %s --sign --mechanism RSA-PKCS --label sss:0xEF00000A --input-file %sdata10.txt --output-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")

    log.info("Verifying data with length 10 bytes with key: %s algo: RSA-PKCS" % (args.key_type))
    run("%s --module %s --verify --mechanism RSA-PKCS --label sss:0xEF00000A --input-file %sdata10.txt --signature-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")


    log.info("Signing data with length 10 bytes with key: %s algo: RSA-PKCS-PSS" % (args.key_type)) # Only SHA1 data
    run("%s --module %s --sign --mechanism RSA-PKCS-PSS --label sss:0xEF00000A --input-file %sdata20.txt --output-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")

    log.info("Verifying data with length 10 bytes with key: %s algo: RSA-PKCS-PSS" % (args.key_type))
    run("%s --module %s --verify --mechanism RSA-PKCS-PSS --label sss:0xEF00000A --input-file %sdata20.txt --signature-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")


    for algo in algorithms_RSA_PKCS:

        log.info("Signing data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo)) # Only SHA1 data
        run("%s --module %s --sign --mechanism %s --label sss:0xEF00000A --input-file %sdata1024.txt --output-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

        log.info("Verifying data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo))
        run("%s --module %s --verify --mechanism %s --label sss:0xEF00000A --input-file %sdata1024.txt --signature-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")


    for algo in algorithms_RSA_PKCS_PSS:

        if (args.key_type.lower() == "rsa:1024") and (algo == "SHA512-RSA-PKCS-PSS"):
            continue

        log.info("Signing data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo)) # Only SHA1 data
        run("%s --module %s --sign --mechanism %s --label sss:0xEF00000A --input-file %sdata1024.txt --output-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

        log.info("Verifying data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo))
        run("%s --module %s --verify --mechanism %s --label sss:0xEF00000A --input-file %sdata1024.txt --signature-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")


    log.info("Deleting generated keypair")
    run("%s --module %s --delete-object --type privkey --label sss:0xEF00000A" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()
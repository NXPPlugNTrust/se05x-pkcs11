/*
 * Copyright 2021 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "sss_pkcs11_pal.h"

/* ********************** Local Defines ********************** */

/**
 * Defines OpenSC NON_REPUDIATION attribute
 */
#define SC_VENDOR_DEFINED 0x4F534300 /* OSC */
// CKA_OPENSC_NON_REPUDIATION for OpenSC 0.17
#define CKA_OPENSC_NON_REPUDIATION_0_17 (CKA_VENDOR_DEFINED | 1UL)
// CKA_OPENSC_NON_REPUDIATION for OpenSC 0.21
#define CKA_OPENSC_NON_REPUDIATION_0_21 (CKA_VENDOR_DEFINED | SC_VENDOR_DEFINED | 1UL)

/* ********************** Public Functions ********************** */

extern CK_RV pkcs11_read_object_size(uint32_t keyId, uint16_t *keyLen);

/**
 * @brief Free resources attached to an object handle.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE xObject)
{
    (void)(xSession);
    LOG_D("%s", __FUNCTION__);

    CK_RV xResult           = CKR_FUNCTION_FAILED;
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_object_t object     = {0};

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_pkcs11_mutex_lock() == 0, xResult, CKR_CANT_LOCK);

    sss_status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    ENSURE_OR_GO_EXIT(xObject <= UINT32_MAX);
    sss_status = sss_key_object_get_handle(&object, (uint32_t)xObject);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &object);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    xResult = CKR_OK;
exit:
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Provides import and storage of a single client certificate and
 * associated private key.
 */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(CK_SESSION_HANDLE xSession, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pxObject)
{
    AX_UNUSED_ARG(xSession);
    CK_RV xResult = CKR_FUNCTION_FAILED;
    LOG_D("%s", __FUNCTION__);
    sss_pkcs11_key_parse_t keyParse = {0};
    U8 buff[4096]                   = {0};
    CK_ULONG Valueindex             = 0;
    uint32_t keyId                  = 0xffffffff;
    CK_ULONG i                      = 0;
    CK_ULONG classIndex             = 0;
    size_t buff_len                 = sizeof(buff);
    CK_ULONG keyidindex;
    CK_ULONG labelIndex = 0;
    CK_BBOOL foundKeyId = CK_FALSE;
    sss_status_t status;
    sss_cipher_type_t cipherType = kSSS_CipherType_RSA;
    sss_key_part_t keyPart       = kSSS_KeyPart_NONE;
    CK_KEY_TYPE key_type;
    CK_ULONG index;
    sss_object_t tmp_object = {0};

    keyParse.pbuff = &buff[0];

    /*
     * Check parameters.
     */
    ENSURE_OR_RETURN_ON_ERROR(pkcs11CREATEOBJECT_MINIMUM_ATTRIBUTE_COUNT <= ulCount, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(pxTemplate != NULL, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(pxObject != NULL, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(ulCount != (CK_ULONG)-1, CKR_ARGUMENTS_BAD);

    ENSURE_OR_RETURN_ON_ERROR(
        pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_CLASS, &classIndex) == CKR_OK,
        CKR_FUNCTION_FAILED);

    /*Find the key id as it's needed while provisiong keys and certificate*/
    if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_SSS_ID, &keyidindex) == CKR_OK) {
        foundKeyId = CK_TRUE;
    }

    /*
     * Handle the object by class.
     */
    switch (*((uint32_t *)pxTemplate[classIndex].pValue)) {
    case CKO_CERTIFICATE: {
        ENSURE_OR_GO_EXIT(pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_VALUE, &i) == CKR_OK);

        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(pxTemplate[i].ulValueLen < buff_len, xResult, CKR_HOST_MEMORY);
        memcpy(buff, pxTemplate[i].pValue, pxTemplate[i].ulValueLen);
        buff_len = (size_t)pxTemplate[i].ulValueLen;

        if (0 != pxTemplate[i].ulValueLen) {
            if (!foundKeyId) {
                if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                    /* CKA_LABEL was not provided. Generate a random keyId */
                    ENSURE_OR_GO_EXIT(pkcs11_label_to_keyId((unsigned char *)"", 0, &keyId) == CKR_OK);
                }
                else {
                    ENSURE_OR_GO_EXIT(
                        pkcs11_label_to_keyId(
                            pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) == CKR_OK);
                }
            }
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(pkcs11_parse_Cert(&buff[0], buff_len) == 0, xResult, CKR_ARGUMENTS_BAD);

            status = pkcs11_sss_create_token(&pex_sss_demo_boot_ctx->ks,
                &tmp_object,
                keyId,
                kSSS_KeyPart_Default,
                kSSS_CipherType_Binary,
                buff,
                buff_len,
                buff_len * 8);
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);
            *pxObject = keyId;
        }
        break;
    }
    case CKO_PRIVATE_KEY: {
        /* Parses the private key in PEM format and converts it to DER format.
         * This is required because as SE shall require a key pair for storing keys
         */
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            pkcs11_parse_PrivateKey(pxTemplate, ulCount, &Valueindex, &keyParse) == 0, xResult, CKR_ARGUMENTS_BAD);

        if (!foundKeyId) {
            if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                /* CKA_LABEL was not provided. Generate a random keyId */
                ENSURE_OR_GO_EXIT(pkcs11_label_to_keyId((unsigned char *)"", 0, &keyId) == CKR_OK);
            }
            else {
                ENSURE_OR_GO_EXIT(
                    pkcs11_label_to_keyId(pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) ==
                    CKR_OK);
            }
        }

        if (keyParse.cipherType == kSSS_CipherType_EC_NIST_P) {
            keyPart = kSSS_KeyPart_Private;
        }
        else {
            keyPart = kSSS_KeyPart_Pair;
        }
        ENSURE_OR_GO_EXIT((keyParse.buffLen) <= UINT32_MAX);
        ENSURE_OR_GO_EXIT((keyParse.keyBitLen) <= UINT32_MAX);
        status = pkcs11_sss_create_token(&pex_sss_demo_boot_ctx->ks,
            &tmp_object,
            keyId,
            keyPart,
            keyParse.cipherType,
            keyParse.pbuff,
            keyParse.buffLen,
            keyParse.keyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        *pxObject = keyId;
        break;
    }
    case CKO_PUBLIC_KEY: {
        /* Parses the public key in PEM format and converts it to DER format. */
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            pkcs11_parse_PublicKey(pxTemplate, ulCount, &Valueindex, &keyParse) == 0, xResult, CKR_ARGUMENTS_BAD);

        if (!foundKeyId) {
            if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                /* CKA_LABEL was not provided. Generate a random keyId */
                ENSURE_OR_GO_EXIT(pkcs11_label_to_keyId((unsigned char *)"", 0, &keyId) == CKR_OK);
            }
            else {
                ENSURE_OR_GO_EXIT(
                    pkcs11_label_to_keyId(pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) ==
                    CKR_OK);
            }
        }

        ENSURE_OR_GO_EXIT((keyParse.buffLen) <= UINT32_MAX);
        ENSURE_OR_GO_EXIT((keyParse.keyBitLen) <= UINT32_MAX);
        status = pkcs11_sss_create_token(&pex_sss_demo_boot_ctx->ks,
            &tmp_object,
            keyId,
            kSSS_KeyPart_Public,
            keyParse.cipherType,
            keyParse.pbuff,
            keyParse.buffLen,
            keyParse.keyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        *pxObject = keyId;
        break;
    }
    case CKO_SECRET_KEY: {
        if (!foundKeyId) {
            if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                /* CKA_LABEL was not provided. Generate a random keyId */
                ENSURE_OR_GO_EXIT(pkcs11_label_to_keyId((unsigned char *)"", 0, &keyId) == CKR_OK);
            }
            else {
                ENSURE_OR_GO_EXIT(
                    pkcs11_label_to_keyId(pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) ==
                    CKR_OK);
            }
        }
        ENSURE_OR_GO_EXIT(pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_VALUE, &i) == CKR_OK);
        index = 0;
        ENSURE_OR_GO_EXIT(pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_KEY_TYPE, &index) == CKR_OK);
        memcpy(&key_type, pxTemplate[index].pValue, pxTemplate[index].ulValueLen);
        /* Check for HMAC Keytype */
        if (key_type == CKK_SHA256_HMAC) {
            cipherType = kSSS_CipherType_HMAC;
        }
        else {
            cipherType = kSSS_CipherType_AES;
        }
        if (0 != pxTemplate[i].ulValueLen) {
            sss_object_t secretObject = {0};
            ENSURE_OR_GO_EXIT((pxTemplate[i].ulValueLen) <= (UINT32_MAX / 8));
            status = pkcs11_sss_create_token(&pex_sss_demo_boot_ctx->ks,
                &secretObject,
                keyId,
                kSSS_KeyPart_Default,
                cipherType,
                (uint8_t *)pxTemplate[i].pValue,
                pxTemplate[i].ulValueLen,
                pxTemplate[i].ulValueLen * 8);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            *pxObject = keyId;
        }
        break;
    }
    default:
        goto exit;
    }

    xResult = CKR_OK;
exit:
    return xResult;
}

/**
 * @brief Begin an enumeration sequence for the objects of the specified type.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(CK_SESSION_HANDLE xSession, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount)
{
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    int classIndex            = 0;
    CK_BBOOL foundClass       = CK_FALSE;
    CK_ULONG i                = 0;
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);

    /*
     * Allow filtering on a single object class attribute.
     */
    pxSession->xFindObjectInit    = CK_TRUE;
    pxSession->xFindObjectClass   = pkcs11INVALID_OBJECT_CLASS; /* Invalid Class */
    pxSession->xFindObjectKeyType = pkcs11INVALID_KEY_TYPE;     /* Invalid Key Type */

    if (!pxTemplate) {
        pxSession->labelPresent          = CK_FALSE;
        pxSession->keyIdPresent          = CK_FALSE;
        pxSession->xFindObjectClass      = pkcs11INVALID_OBJECT_CLASS; /* Invalid Class */
        pxSession->xFindObjectKeyType    = pkcs11INVALID_KEY_TYPE;     /* Invalid Key Type */
        pxSession->xFindObjectTotalFound = 0;
        return CKR_OK;
    }

    for (i = 0; i < ulCount; i++) {
        if (pxTemplate[i].type == CKA_LABEL) {
            pxSession->labelPresent = CK_TRUE;
            if (snprintf(pxSession->label, sizeof(pxSession->label), "%s", (char *)pxTemplate[i].pValue) < 0) {
                LOG_E("snprintf error");
                pxSession->labelPresent = CK_FALSE;
                pxSession->labelLen     = 0;
                continue;
            }
            pxSession->labelLen = pxTemplate[i].ulValueLen;
        }
        else if (pxTemplate[i].type == CKA_CLASS) {
            classIndex = i;
            foundClass = CK_TRUE;
        }
        else if (pxTemplate[i].type == CKA_SSS_ID || pxTemplate[i].type == CKA_ID) {
            pxSession->keyIdPresent = CK_TRUE;
            pxSession->keyId        = *((uint32_t *)(pxTemplate[i].pValue));
        }
        else if (pxTemplate[i].type == CKA_KEY_TYPE) {
            memcpy(&pxSession->xFindObjectKeyType, pxTemplate[i].pValue, sizeof(CK_KEY_TYPE));
        }
    }
    if (foundClass) {
        memcpy(&pxSession->xFindObjectClass, pxTemplate[classIndex].pValue, sizeof(CK_OBJECT_CLASS));
    }

    return CKR_OK;
}

/**
 * @brief Query the objects of the requested type.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE_PTR pxObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    CK_RV xResult             = CKR_OK;
    bool xDone                = false;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    uint32_t keyId            = 0x0;

    LOG_D("%s", __FUNCTION__);

    // Check parameters.
    if (pxSession == NULL) {
        xResult = CKR_SESSION_HANDLE_INVALID;
        return xResult;
    }

    if ((CK_BBOOL)CK_FALSE == pxSession->xFindObjectInit) {
        xResult = CKR_OPERATION_NOT_INITIALIZED;
        return xResult;
    }

    if ((false == xDone) && (0u == ulMaxObjectCount)) {
        xResult = CKR_ARGUMENTS_BAD;
        xDone   = true;
        return xResult;
    }

    if ((false == xDone) && (!pxObject || !pulObjectCount)) {
        xResult = CKR_ARGUMENTS_BAD;
        xDone   = true;
        return xResult;
    }

    /*
     * Load object based on whether label / keyId was passed.
     * If neither was passed while initializing FindObjects operation
     * then we list the objects present on the secure element and filter
     * out based on object type required by the application.
     */
    if ((false == xDone) && pxSession->labelPresent) {
        if (pxSession->labelLen == 0) {
            *pulObjectCount = 0;
            xResult         = CKR_FUNCTION_FAILED;
        }
        else {
            if (pxSession->xFindObjectTotalFound == 1) {
                *pulObjectCount = 0;
            }
            else {
                xResult = pkcs11_label_to_keyId((unsigned char *)pxSession->label, pxSession->labelLen, &keyId);
                if (xResult == CKR_OK) {
                    sss_status_t status = kStatus_SSS_Fail;
                    sss_object_t object = {0};
                    if (sss_pkcs11_mutex_lock() != 0) {
                        xResult = CKR_CANT_LOCK;
                        return xResult;
                    }
                    status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
                    if (status != kStatus_SSS_Success) {
                        xResult = CKR_FUNCTION_FAILED;
                    }
                    else {
                        status = sss_key_object_get_handle(&object, keyId);
                        if (status != kStatus_SSS_Success) {
                            *pulObjectCount = 0;
                        }
                        else {
                            *pxObject                        = keyId;
                            *pulObjectCount                  = 1;
                            pxSession->xFindObjectTotalFound = 1;

                            pxSession->pCurrentKs = (SwKeyStorePtr_t)SSS_MALLOC(sizeof(SwKeyStore_t));
                            memset(pxSession->pCurrentKs, 0, sizeof(SwKeyStore_t));
                            memcpy(&pxSession->pCurrentKs->SSSObjects[0],
                                &object,
                                sizeof(pxSession->pCurrentKs->SSSObjects[0]));
                            pxSession->pCurrentKs->keyIdListLen = 1;
                        }
                    }
                    if (sss_pkcs11_mutex_unlock() != 0) {
                        return CKR_FUNCTION_FAILED;
                    }
                }
            }
        }
        xDone = true;
    }
    else if ((false == xDone) && pxSession->keyIdPresent) {
        keyId               = pxSession->keyId;
        sss_status_t status = kStatus_SSS_Fail;
        sss_object_t object = {0};

        if (pxSession->xFindObjectTotalFound == 1) {
            *pulObjectCount = 0;
        }
        else {
            if (sss_pkcs11_mutex_lock() != 0) {
                xResult = CKR_CANT_LOCK;
                return xResult;
            }
            status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
            if (status != kStatus_SSS_Success) {
                xResult = CKR_FUNCTION_FAILED;
            }
            else {
                status = sss_key_object_get_handle(&object, keyId);
                if (status != kStatus_SSS_Success) {
                    *pulObjectCount = 0;
                }
                else {
                    *pxObject                        = keyId;
                    *pulObjectCount                  = 1;
                    pxSession->xFindObjectTotalFound = 1;

                    pxSession->pCurrentKs = (SwKeyStorePtr_t)SSS_MALLOC(sizeof(SwKeyStore_t));
                    memset(pxSession->pCurrentKs, 0, sizeof(SwKeyStore_t));
                    memcpy(
                        &pxSession->pCurrentKs->SSSObjects[0], &object, sizeof(pxSession->pCurrentKs->SSSObjects[0]));
                    pxSession->pCurrentKs->keyIdListLen = 1;
                }
            }
            if (sss_pkcs11_mutex_unlock() != 0) {
                return CKR_FUNCTION_FAILED;
            }
        }

        xDone = true;
    }

    else if ((false == xDone)) {
        if (MAX_ID_LIST_SIZE < ulMaxObjectCount) {
            LOG_E("More than MAX_ID_LIST_SIZE objects requested");
            xResult = CKR_ARGUMENTS_BAD;
            xDone   = true;
            return xResult;
        }
    retry:
        xResult                                            = CKR_OK;
        static uint32_t object_list[USER_MAX_ID_LIST_SIZE] = {0};
        static size_t object_list_size                     = 0;

        if (pxSession->xFindObjectOutputOffset % USER_MAX_ID_LIST_SIZE == 0) {
            memset(object_list, 0, sizeof(object_list));
            object_list_size     = sizeof(object_list) / sizeof(object_list[0]);
            smStatus_t sm_status = pkcs11_read_id_list(xSession, object_list, &object_list_size, ulMaxObjectCount);
            if (sm_status != SM_OK) {
                *pulObjectCount = 0;
                xResult         = CKR_OK;
                xDone           = true;
                return xResult;
            }
            /* Read ID List was successful. Update SW Keystore for further operations */
            if (pxSession->pCurrentKs == NULL){
                pxSession->pCurrentKs = (SwKeyStorePtr_t)SSS_MALLOC(sizeof(SwKeyStore_t));
            }
            if (!pxSession->pCurrentKs) {
                xResult = CKR_HOST_MEMORY;
                xDone   = true;
                return xResult;
            }
            memset(pxSession->pCurrentKs, 0, sizeof(SwKeyStore_t));
            for (size_t i = 0; i < object_list_size; i++) {
                pxSession->pCurrentKs->keyIdListLen = i + 1;
                sss_object_t object;
                sss_status_t status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
                if (status != kStatus_SSS_Success) {
                    LOG_E("Object init failed. Should not reach here");
                    continue;
                }
                status = sss_key_object_get_handle(&object, object_list[i]);
                if (status != kStatus_SSS_Success) {
                    LOG_E("Object get handle failed for 0x%08X", object_list[i]);
                    continue;
                }
                memcpy(&pxSession->pCurrentKs->SSSObjects[i], &object, sizeof(pxSession->pCurrentKs->SSSObjects[0]));
            }
        }

        size_t i                       = 0;
        CK_OBJECT_HANDLE_PTR ckObjects = (CK_OBJECT_HANDLE_PTR)SSS_MALLOC(sizeof(CK_OBJECT_HANDLE) * ulMaxObjectCount);
        *pulObjectCount                = 0;
        if (!ckObjects) {
            xResult = CKR_HOST_MEMORY;
            xDone   = true;
            return xResult;
        }
        memset(ckObjects, 0, sizeof(CK_OBJECT_HANDLE) * ulMaxObjectCount);

        if (sss_pkcs11_mutex_lock() != 0) {
            xResult = CKR_CANT_LOCK;
            return xResult;
        }
        for (i = (pxSession->xFindObjectOutputOffset % USER_MAX_ID_LIST_SIZE);
             ((i < object_list_size) && (*pulObjectCount < ulMaxObjectCount));
             i++) {
            uint32_t id = object_list[i];
            sss_object_t *pObject;

            pxSession->xFindObjectOutputOffset++;
            pObject = &pxSession->pCurrentKs->SSSObjects[i];

            if (pObject->keyId == 0) {
                continue;
            }
            if (pxSession->xFindObjectClass == pkcs11INVALID_OBJECT_CLASS &&
                pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                /* For public key attributes */
                if (pxSession->pFindObject->xSetPublicKey == CK_TRUE) {
                    memcpy(&ckObjects[*pulObjectCount], &pxSession->pFindObject->keyPairObjHandle, sizeof(id));
                    (*pulObjectCount)++;
                    pxSession->pFindObject->xSetPublicKey = CK_FALSE;
                }
                else {
                    memcpy(&ckObjects[*pulObjectCount], &id, sizeof(id));
                    (*pulObjectCount)++;
                    /* For public key attributes */
                    if (pObject->objectType == kSSS_KeyPart_Pair) {
                        pxSession->pFindObject->keyPairObjHandle = id;
                        pxSession->pFindObject->xSetPublicKey    = CK_TRUE;
                        /* We have maintained object cache having same object for keypair type
                            * So, for private/public key there will be same keyobject.
                            * Here xFindObjectOutputOffset is decremented so that it points to the
                            * public key instead of pointing to the next object.
                            */
                        pxSession->xFindObjectOutputOffset--;
                    }
                }
            }
            else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                     pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                CK_BBOOL isX509Cert = CK_FALSE;
                if (pObject->cipherType == kSSS_CipherType_Binary) {
                    isX509Cert = pkcs11_is_X509_certificate(id);
                }
                if ((pObject->cipherType == kSSS_CipherType_Binary && isX509Cert == CK_TRUE &&
                        pxSession->xFindObjectClass == CKO_CERTIFICATE) ||
                    (pObject->objectType == kSSS_KeyPart_Pair && (pxSession->xFindObjectClass == CKO_PRIVATE_KEY ||
                                                                     pxSession->xFindObjectClass == CKO_PUBLIC_KEY)) ||
                    (pObject->objectType == kSSS_KeyPart_Public && pxSession->xFindObjectClass == CKO_PUBLIC_KEY)) {
                    memcpy(&ckObjects[*pulObjectCount], &id, sizeof(id));
                    (*pulObjectCount)++;
                }
            }
            else if (pxSession->xFindObjectClass == pkcs11INVALID_OBJECT_CLASS &&
                     pxSession->xFindObjectKeyType != pkcs11INVALID_KEY_TYPE) {
                if ((pObject->cipherType == kSSS_CipherType_AES && pxSession->xFindObjectKeyType == CKK_AES) ||
                    (pObject->cipherType == kSSS_CipherType_DES && pxSession->xFindObjectKeyType == CKK_DES) ||
                    (pObject->cipherType == kSSS_CipherType_DES && pxSession->xFindObjectKeyType == CKK_DES2) ||
                    (pObject->cipherType == kSSS_CipherType_DES && pxSession->xFindObjectKeyType == CKK_DES3) ||
                    (pObject->cipherType == kSSS_CipherType_RSA && pxSession->xFindObjectKeyType == CKK_RSA) ||
                    (pObject->cipherType == kSSS_CipherType_RSA_CRT && pxSession->xFindObjectKeyType == CKK_RSA) ||
                    (pObject->cipherType == kSSS_CipherType_EC_NIST_P && pxSession->xFindObjectKeyType == CKK_EC)) {
                    memcpy(&ckObjects[*pulObjectCount], &id, sizeof(id));
                    (*pulObjectCount)++;
                }
            }
            else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                     pxSession->xFindObjectKeyType != pkcs11INVALID_KEY_TYPE) {
                CK_BBOOL isX509Cert = CK_FALSE;
                if (pObject->cipherType == kSSS_CipherType_Binary) {
                    isX509Cert = pkcs11_is_X509_certificate(id);
                }
                if ((pObject->cipherType == kSSS_CipherType_Binary && isX509Cert == CK_TRUE &&
                        pxSession->xFindObjectClass == CKO_CERTIFICATE) ||
                    (pObject->objectType == kSSS_KeyPart_Pair && (pxSession->xFindObjectClass == CKO_PRIVATE_KEY ||
                                                                     pxSession->xFindObjectClass == CKO_PUBLIC_KEY)) ||
                    (pObject->objectType == kSSS_KeyPart_Public && pxSession->xFindObjectClass == CKO_PUBLIC_KEY)) {
                    if ((pObject->cipherType == kSSS_CipherType_AES && pxSession->xFindObjectKeyType == CKK_AES) ||
                        (pObject->cipherType == kSSS_CipherType_DES && pxSession->xFindObjectKeyType == CKK_DES) ||
                        (pObject->cipherType == kSSS_CipherType_DES && pxSession->xFindObjectKeyType == CKK_DES2) ||
                        (pObject->cipherType == kSSS_CipherType_DES && pxSession->xFindObjectKeyType == CKK_DES3) ||
                        (pObject->cipherType == kSSS_CipherType_RSA && pxSession->xFindObjectKeyType == CKK_RSA) ||
                        (pObject->cipherType == kSSS_CipherType_RSA_CRT && pxSession->xFindObjectKeyType == CKK_RSA) ||
                        (pObject->cipherType == kSSS_CipherType_EC_NIST_P && pxSession->xFindObjectKeyType == CKK_EC)) {
                        memcpy(&ckObjects[*pulObjectCount], &id, sizeof(id));
                        (*pulObjectCount)++;
                    }
                }
            }
        }
        if (sss_pkcs11_mutex_unlock() != 0) {
            SSS_FREE(ckObjects);
            return CKR_FUNCTION_FAILED;
        }

        if (*pulObjectCount > 0) {
            memcpy(pxObject, ckObjects, (sizeof(CK_OBJECT_HANDLE) * (*pulObjectCount)));
            pxSession->xFindObjectTotalFound = pxSession->xFindObjectTotalFound + *pulObjectCount;
        }
        else if (pxSession->xFindObjectOutputOffset % USER_MAX_ID_LIST_SIZE == 0) {
            if (ckObjects) {
                SSS_FREE(ckObjects);
            }
            goto retry;
        }
        if (ckObjects) {
            SSS_FREE(ckObjects);
        }
        xDone = true;
    }
    return xResult;
}

/**
 * @brief Terminate object enumeration.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE xSession)
{
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR((CK_BBOOL)CK_FALSE != pxSession->xFindObjectInit, CKR_OPERATION_NOT_INITIALIZED);

    LOG_D("%s", __FUNCTION__);

    /*
    * Clean-up find objects state.
    */
    pxSession->labelPresent            = CK_FALSE;
    pxSession->keyIdPresent            = CK_FALSE;
    pxSession->xFindObjectInit         = CK_FALSE;
    pxSession->xFindObjectClass        = 0;
    pxSession->xFindObjectTotalFound   = 0;
    pxSession->xFindObjectKeyType      = pkcs11INVALID_KEY_TYPE;
    pxSession->xFindObjectOutputOffset = 0;

    if (NULL != pxSession->pCurrentKs) {
        SSS_FREE(pxSession->pCurrentKs);
        pxSession->pCurrentKs = NULL;
    }
    return CKR_OK;
}

/**
 * @brief Create a new object by copying existing object.
 */
// LCOV_EXCL_START
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)
(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(hObject);
    AX_UNUSED_ARG(pTemplate);
    AX_UNUSED_ARG(ulCount);
    AX_UNUSED_ARG(phNewObject);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}
// LCOV_EXCL_STOP

/**
 * @brief Generates a secret key.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)
(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    /*
        Attribute.CLASS: ObjectClass.SECRET_KEY,
        Attribute.ID: id or b'',
        Attribute.LABEL: label or '',
        Attribute.TOKEN: store,
        Attribute.PRIVATE: True,
        Attribute.SENSITIVE: True,
        Attribute.ENCRYPT: MechanismFlag.ENCRYPT & capabilities,
        Attribute.DECRYPT: MechanismFlag.DECRYPT & capabilities,
        Attribute.WRAP: MechanismFlag.WRAP & capabilities,
        Attribute.UNWRAP: MechanismFlag.UNWRAP & capabilities,
        Attribute.SIGN: MechanismFlag.SIGN & capabilities,
        Attribute.VERIFY: MechanismFlag.VERIFY & capabilities,
        Attribute.DERIVE: MechanismFlag.DERIVE & capabilities,
        template_[Attribute.VALUE_LEN] = key_length // 8  # In bytes
    */
    CK_RV xResult           = CKR_FUNCTION_FAILED;
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx;
    uint32_t keyId               = 0x0;
    size_t keyLen                = 0;
    sss_cipher_type_t cipherType = kSSS_CipherType_NONE;
    CK_ULONG attributeIndex      = 0;
    CK_OBJECT_CLASS ck_object    = pkcs11INVALID_OBJECT_CLASS;
    CK_MECHANISM mech            = *pMechanism;
    uint8_t randomKey[64]        = {0};
    sss_object_t sss_object      = {0};

    AX_UNUSED_ARG(hSession);
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_GO_EXIT(pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_CLASS, &attributeIndex) == CKR_OK);

    /* Ensure that CK_OBJECT_CLASS is CKO_SECRET_KEY */
    ck_object = *((CK_OBJECT_CLASS_PTR)pTemplate[attributeIndex].pValue);
    ENSURE_OR_GO_EXIT(ck_object == CKO_SECRET_KEY);

    if (mech.mechanism == CKM_AES_KEY_GEN) {
        ENSURE_OR_GO_EXIT(
            pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_VALUE_LEN, &attributeIndex) == CKR_OK);

        keyLen = *((size_t *)pTemplate[attributeIndex].pValue);
        if ((keyLen != 16) && (keyLen != 24) && (keyLen != 32)) {
            LOG_E("Unsupported key length %d", keyLen);
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }

        cipherType = kSSS_CipherType_AES;
    }
    else if (mech.mechanism == CKM_DES2_KEY_GEN) {
        keyLen     = 16; /* Fixed length for DES key */
        cipherType = kSSS_CipherType_DES;
    }
    else if (mech.mechanism == CKM_DES3_KEY_GEN) {
        keyLen     = 24; /* Fixed length for DES key */
        cipherType = kSSS_CipherType_DES;
    }

    xResult = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_LABEL, &attributeIndex);
    if (xResult != CKR_OK) {
        /* CKA_LABEL was not provided. Generate a random keyId */
        xResult = pkcs11_label_to_keyId((unsigned char *)"", 0, &keyId);
        ENSURE_OR_GO_EXIT(xResult == CKR_OK);
    }
    else {
        xResult = pkcs11_label_to_keyId(pTemplate[attributeIndex].pValue, pTemplate[attributeIndex].ulValueLen, &keyId);
        ENSURE_OR_GO_EXIT(xResult == CKR_OK);
    }

    /* Generate random data */
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_pkcs11_mutex_lock() == 0, xResult, CKR_CANT_LOCK);

    sss_status = sss_rng_context_init(&sss_rng_ctx, &pex_sss_demo_boot_ctx->session);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);

    sss_status = sss_rng_get_random(&sss_rng_ctx, randomKey, keyLen);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_pkcs11_mutex_unlock() == 0, xResult, CKR_CANT_LOCK);

    /* Import secret key */
    sss_status = pkcs11_sss_create_token(&pex_sss_demo_boot_ctx->ks,
        &sss_object,
        keyId,
        kSSS_KeyPart_Default,
        cipherType,
        randomKey,
        keyLen,
        keyLen * 8);
    if (sss_status == kStatus_SSS_Success) {
        *phKey = keyId;
    }
    else {
        goto exit;
    }

    xResult = CKR_OK;
exit:
    return xResult;
}

/**
 * @brief Generates a public-key/private-key pair.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV xResult                      = CKR_OK;
    P11SessionPtr_t pxSession          = prvSessionPointerFromHandle(hSession);
    size_t KeyBitLen                   = 0;
    CK_ULONG privateLabelIndex         = 0;
    CK_ULONG publicLabelIndex          = 0;
    uint32_t privKeyId                 = 0;
    uint32_t pubKeyId                  = 0;
    sss_status_t sss_status            = kStatus_SSS_Fail;
    sss_object_t sss_object            = {0};
    CK_BBOOL skipPublicKey             = CK_FALSE;
    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)(&(pex_sss_demo_boot_ctx->session));
    SE05x_Result_t IdExists            = kSE05x_Result_NA;
    sss_cipher_type_t cipherType       = kSSS_CipherType_Binary;

    LOG_D("%s", __FUNCTION__);

    if (pxSession == NULL) {
        xResult = CKR_SESSION_HANDLE_INVALID;
        return xResult;
    }

    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism) {
    case CKM_EC_KEY_PAIR_GEN:
        cipherType = kSSS_CipherType_EC_NIST_P;
        break;
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        cipherType = kSSS_CipherType_RSA;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (cipherType == kSSS_CipherType_EC_NIST_P) {
        CK_ULONG ec_params_index = 0;
        uint8_t ec_params[40]    = {""};
        xResult                  = pkcs11_get_attribute_parameter_index(
            pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_EC_PARAMS, &ec_params_index);
        if (xResult != CKR_OK) {
            return xResult;
        }

        if (pPublicKeyTemplate[ec_params_index].ulValueLen > sizeof(ec_params)) {
            goto exit;
        }
        memcpy(ec_params, pPublicKeyTemplate[ec_params_index].pValue, pPublicKeyTemplate[ec_params_index].ulValueLen);

        uint8_t tag     = ASN_TAG_OBJ_IDF;
        uint8_t oid[20] = {0};
        size_t oidLen   = sizeof(oid);
        xResult         = pkcs11_setASNTLV(
            tag, (uint8_t *)MBEDTLS_OID_EC_GRP_SECP192R1, sizeof(MBEDTLS_OID_EC_GRP_SECP192R1) - 1, oid, &oidLen);
        if (xResult != CKR_OK) {
            return xResult;
        }

        if (sizeof(oid) > oidLen) {
            if (memcmp(&oid[oidLen], &ec_params[0], sizeof(oid) - oidLen) == 0) {
                KeyBitLen = 192;
                goto cont;
            }
        }

        oidLen = sizeof(oid);

        xResult = pkcs11_setASNTLV(
            tag, (uint8_t *)MBEDTLS_OID_EC_GRP_SECP224R1, sizeof(MBEDTLS_OID_EC_GRP_SECP224R1) - 1, oid, &oidLen);
        if (xResult != CKR_OK) {
            return xResult;
        }

        if (sizeof(oid) > oidLen) {
            if (memcmp(&oid[oidLen], &ec_params[0], sizeof(oid) - oidLen) == 0) {
                KeyBitLen = 224;
                goto cont;
            }
        }
        oidLen = sizeof(oid);

        xResult = pkcs11_setASNTLV(
            tag, (uint8_t *)MBEDTLS_OID_EC_GRP_SECP256R1, sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) - 1, oid, &oidLen);
        if (xResult != CKR_OK) {
            return xResult;
        }

        if (sizeof(oid) > oidLen) {
            if (memcmp(&oid[oidLen], &ec_params[0], sizeof(oid) - oidLen) == 0) {
                KeyBitLen = 256;
                goto cont;
            }
        }

        oidLen = sizeof(oid);

        xResult = pkcs11_setASNTLV(
            tag, (uint8_t *)MBEDTLS_OID_EC_GRP_SECP384R1, sizeof(MBEDTLS_OID_EC_GRP_SECP384R1) - 1, oid, &oidLen);
        if (xResult != CKR_OK) {
            return xResult;
        }

        if (sizeof(oid) > oidLen) {
            if (memcmp(&oid[oidLen], &ec_params[0], sizeof(oid) - oidLen) == 0) {
                KeyBitLen = 384;
                goto cont;
            }
        }
        oidLen = sizeof(oid);

        xResult = pkcs11_setASNTLV(
            tag, (uint8_t *)MBEDTLS_OID_EC_GRP_SECP521R1, sizeof(MBEDTLS_OID_EC_GRP_SECP521R1) - 1, oid, &oidLen);
        if (xResult != CKR_OK) {
            return xResult;
        }

        if (sizeof(oid) > oidLen) {
            if (memcmp(&oid[oidLen], &ec_params[0], sizeof(oid) - oidLen) == 0) {
                KeyBitLen = 521;
                goto cont;
            }
        }

        return CKR_ARGUMENTS_BAD;
    }
    else if (cipherType == kSSS_CipherType_RSA) {
        CK_ULONG rsa_params_index = 0;
        xResult                   = pkcs11_get_attribute_parameter_index(
            pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_MODULUS_BITS, &rsa_params_index);
        if (xResult != CKR_OK) {
            return xResult;
        }

        CK_ULONG modulusBits = 0;
        memcpy(
            &modulusBits, pPublicKeyTemplate[rsa_params_index].pValue, pPublicKeyTemplate[rsa_params_index].ulValueLen);

        KeyBitLen = (size_t)modulusBits;

        if ((KeyBitLen != 1024) && (KeyBitLen != 2048) && (KeyBitLen != 3072) && (KeyBitLen != 4096)) {
            return CKR_ARGUMENTS_BAD;
        }
    }

cont:

    xResult = pkcs11_get_attribute_parameter_index(
        pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_LABEL, &privateLabelIndex);
    if (xResult != CKR_OK) {
        /* CKA_LABEL was not provided. Check if CKA_ID was passed */
        xResult = pkcs11_get_attribute_parameter_index(
            pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_ID, &privateLabelIndex);
        if (CKR_OK != xResult) {
            /* CKA_ID was also not provided. Generate a random keyId */
            xResult = pkcs11_label_to_keyId((unsigned char *)"", 0, &privKeyId);
            if (xResult != CKR_OK) {
                return xResult;
            }
        }
        else {
            /* CKA_ID is provided. Use as keyID */
            memcpy((void *)&privKeyId, pPrivateKeyTemplate[privateLabelIndex].pValue, sizeof(privKeyId));
        }
    }
    else {
        xResult = pkcs11_label_to_keyId(pPrivateKeyTemplate[privateLabelIndex].pValue,
            pPrivateKeyTemplate[privateLabelIndex].ulValueLen,
            &privKeyId);
        if (xResult != CKR_OK) {
            return xResult;
        }
    }

    xResult = pkcs11_get_attribute_parameter_index(
        pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_LABEL, &publicLabelIndex);
    if (xResult != CKR_OK) {
        /* CKA_LABEL was not provided. Check if CKA_ID was passed */
        xResult = pkcs11_get_attribute_parameter_index(
            pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_ID, &privateLabelIndex);
        if (CKR_OK != xResult) {
            /* CKA_ID was also not provided. Generate a random keyId */
            xResult = pkcs11_label_to_keyId((unsigned char *)"", 0, &pubKeyId);
            if (xResult != CKR_OK) {
                return xResult;
            }
        }
        else {
            /* CKA_ID is provided. Use as keyID */
            memcpy((void *)&pubKeyId, pPrivateKeyTemplate[privateLabelIndex].pValue, sizeof(pubKeyId));
        }
    }
    else {
        xResult = pkcs11_label_to_keyId(
            pPublicKeyTemplate[publicLabelIndex].pValue, pPublicKeyTemplate[publicLabelIndex].ulValueLen, &pubKeyId);
        if (xResult != CKR_OK) {
            return xResult;
        }
    }
    /* Checking and deleting the key if already present */

    if (SM_OK == Se05x_API_CheckObjectExists(&se05x_session->s_ctx, privKeyId, &IdExists)) {
        if ((IdExists == kSE05x_Result_SUCCESS) && (cipherType == kSSS_CipherType_EC_NIST_P)) {
            LOG_W("Key id 0x%X already exists!!", privKeyId);
            if (SM_OK != Se05x_API_DeleteSecureObject(&se05x_session->s_ctx, privKeyId)) {
                LOG_E("Se05x_API_DeleteSecureObject Failed !!");
                xResult = CKR_FUNCTION_FAILED;
                return xResult;
            }
            else {
                LOG_D("Successfully deleted the key!!");
            }
        }
    }
    else {
        LOG_E("Se05x_API_CheckObjectExists Failed !!");
        xResult = CKR_FUNCTION_FAILED;
        return xResult;
    }

    if (pubKeyId == privKeyId) {
        skipPublicKey = CK_TRUE;
    }

    if (sss_pkcs11_mutex_lock() != 0) {
        xResult = CKR_CANT_LOCK;
        return xResult;
    }

    sss_status = sss_key_object_init(&sss_object, &pex_sss_demo_boot_ctx->ks);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    sss_status = sss_key_object_allocate_handle(
        &sss_object, privKeyId, kSSS_KeyPart_Pair, cipherType, KeyBitLen * 8, kKeyObject_Mode_Persistent);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    sss_status = sss_key_store_generate_key(&pex_sss_demo_boot_ctx->ks, &sss_object, KeyBitLen, NULL);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    if (!skipPublicKey) {
        uint8_t public[2048] = {0};
        size_t public_len    = sizeof(public);

        sss_status = sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, public, &public_len, &KeyBitLen);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }

        sss_object_t sss_pub_object = {0};

        sss_status = sss_key_object_init(&sss_pub_object, &pex_sss_demo_boot_ctx->ks);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }

        sss_status = sss_key_object_allocate_handle(
            &sss_pub_object, pubKeyId, kSSS_KeyPart_Public, cipherType, KeyBitLen * 8, kKeyObject_Mode_Persistent);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }

        sss_status =
            sss_key_store_set_key(&pex_sss_demo_boot_ctx->ks, &sss_pub_object, public, public_len, KeyBitLen, NULL, 0);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }
    }
    else {
        pubKeyId = privKeyId;
    }

    *phPublicKey  = pubKeyId;
    *phPrivateKey = privKeyId;

exit:
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Obtains the size of an object in bytes.
 */
// LCOV_EXCL_START
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(hObject);
    AX_UNUSED_ARG(pulSize);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}
// LCOV_EXCL_STOP

/**
 * @brief Query the value of the specified cryptographic object attribute.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE xObject, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount)
{
    CK_RV xResult             = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    CK_VOID_PTR pvAttr        = NULL;
    CK_ULONG ulAttrLength     = 0;
    CK_ULONG xP11KeyType, iAttrib, objectClass;
    CK_BBOOL supported = CK_FALSE;
    CK_HW_FEATURE_TYPE hwFeatureType;

    LOG_D("%s", __FUNCTION__);

    if (pxSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!pxTemplate) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sss_pkcs11_mutex_lock() != 0) {
        xResult = CKR_CANT_LOCK;
        return xResult;
    }

    for (iAttrib = 0; iAttrib < ulCount && CKR_OK == xResult; iAttrib++) {
        /*
        * Get the attribute data and size.
        */
        ulAttrLength             = 0;
        size_t size              = 0;
        CK_BBOOL infoUnavailable = CK_FALSE;
        sss_object_t sss_object  = {0};
        uint8_t data[2048]       = {0};
        size_t dataLen           = sizeof(data);
        size_t KeyBitLen         = 2048;
        uint8_t *rsaE            = NULL;
        size_t rsaElen;
        uint8_t *rsaN = NULL;
        size_t rsaNlen;
        uint16_t outKeyIndex = 0;
        size_t pubKeyLen;
        char label[80];
        uint32_t keyId = 0;
#if SSS_HAVE_SE05X_VER_GTE_07_02
        uint8_t ObjType     = 0x00;
        uint8_t tag         = 0x00;
        uint8_t ecParam[50] = {0};
#endif //SSS_HAVE_SE05X_VER_GTE_07_02
        CK_CERTIFICATE_TYPE cert_type      = CKC_X_509;
        CK_MECHANISM_TYPE rsa_mechanisms[] = {
            /* RSA Algorithms */
            CKM_RSA_PKCS,
            CKM_SHA1_RSA_PKCS,
            CKM_SHA224_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_RSA_PKCS_PSS,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_SHA224_RSA_PKCS_PSS,
            CKM_SHA256_RSA_PKCS_PSS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
            CKM_RSA_PKCS_OAEP,
        };
        CK_MECHANISM_TYPE aes_mechanisms[] = {
            /* AES Algorithms  */
            CKM_AES_ECB,
            CKM_AES_CBC,
            CKM_AES_CTR,
        };
        CK_MECHANISM_TYPE ecc_mechanisms[] = {
            /* ECDSA */
            CKM_ECDSA,
            CKM_ECDSA_SHA1,
            CKM_ECDSA_SHA224,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
        };
        CK_MECHANISM_TYPE des_mechanisms[] = {
            /* DES Algorithms  */
            CKM_DES_ECB,
            CKM_DES_CBC,
        };
        sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)(&(pex_sss_demo_boot_ctx->session));
#if SSS_HAVE_SE05X_VER_GTE_06_00
        se05x_object_attribute obj_attr = {0};
#endif

        // LOG_I("Attribute required : 0x%08lx\n", pxTemplate[ iAttrib ].type);

        switch (pxTemplate[iAttrib].type) {
        /* Common key attributes */
        case CKA_ID: {
            if (kStatus_SSS_Success != pkcs11_get_validated_object_id(pxSession, xObject, &keyId)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            pvAttr       = &keyId;
            ulAttrLength = sizeof(keyId);
            break;
        }
        case CKA_CERTIFICATE_TYPE: {
            ulAttrLength = sizeof(cert_type);
            pvAttr       = &cert_type;
            break;
        }
        case CKA_LABEL: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            keyId = sss_object.keyId;
            if (snprintf(label, sizeof(label), "sss:%08X", (unsigned int)keyId) < 0) {
                LOG_E("snprintf error");
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            ulAttrLength = strlen(label);
            pvAttr       = (char *)&label[0];
            break;
        }
        case CKA_ALWAYS_AUTHENTICATE: {
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_TOKEN: {
            supported    = CK_TRUE; /* Object is always on token */
            ulAttrLength = sizeof(supported);
            pvAttr       = &(supported);
            break;
        }
        case CKA_KEY_TYPE: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            switch (sss_object.cipherType) {
            case kSSS_CipherType_RSA:
            case kSSS_CipherType_RSA_CRT:
                xP11KeyType = CKK_RSA;
                break;
            case kSSS_CipherType_EC_NIST_P:
            case kSSS_CipherType_EC_NIST_K:
                xP11KeyType = CKK_EC;
                break;
            case kSSS_CipherType_AES:
            case kSSS_CipherType_DES:
                xP11KeyType = CKK_AES;
                break;
            case kSSS_CipherType_HMAC:
                xP11KeyType = CKK_SHA256_HMAC;
                break;
            default:
                xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                break;
            }

            ulAttrLength = sizeof(xP11KeyType);
            pvAttr       = &xP11KeyType;
            break;
        }
        case CKA_VALUE: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            switch (sss_object.cipherType) {
            case kSSS_CipherType_Binary: {
                if (kStatus_SSS_Success !=
                    sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                pvAttr       = (void *)&data[0];
                ulAttrLength = dataLen;
                break;
            }
            case kSSS_CipherType_RSA:
            case kSSS_CipherType_EC_NIST_P: {
                if (sss_object.objectType == kSSS_KeyPart_Pair || sss_object.objectType == kSSS_KeyPart_Private) {
                    ulAttrLength = 0;
                    xResult      = CKR_ATTRIBUTE_SENSITIVE;
                    break;
                }
                if (kStatus_SSS_Success !=
                    sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                pvAttr       = (void *)&data[0];
                ulAttrLength = dataLen;
                break;
            }
            case kSSS_CipherType_AES:
            case kSSS_CipherType_DES: {
                ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                xResult      = CKR_ATTRIBUTE_SENSITIVE;
                LOG_W("Not allowed to readout Symmetric key value");
                break;
            }
            case kSSS_CipherType_HMAC: {
                ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                xResult      = CKR_ATTRIBUTE_SENSITIVE;
                LOG_W("Not allowed to readout HMAC key value");
                break;
            }
            case kSSS_CipherType_Count: {
                if (kStatus_SSS_Success !=
                    sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                // Follow the spec. Increase counter each time its value is read.
                if (SM_OK != Se05x_API_IncCounter(&se05x_session->s_ctx, sss_object.keyId)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                pvAttr       = (void *)&data[0];
                ulAttrLength = dataLen;
                break;
            }
            default: {
                ulAttrLength = 0;
                xResult      = CKR_ARGUMENTS_BAD;
                break;
            }
            }
            break;
        }
        case CKA_VALUE_LEN: {
            pvAttr       = NULL;
            ulAttrLength = 0;
            xResult      = CKR_FUNCTION_FAILED;
            if (xObject > UINT32_MAX) {
                xResult = CKR_FUNCTION_FAILED;
                break;
            }
            xResult = pkcs11_read_object_size(xObject, &outKeyIndex);
            if (xResult != CKR_OK) {
                break;
            }
            size         = (size_t)outKeyIndex;
            pvAttr       = (void *)&size;
            ulAttrLength = sizeof(size_t);
            break;
        }
        case CKA_MODULUS_BITS:
        case CKA_PRIME_BITS: { /*
            * Key strength size query, handled the same for RSA or ECDSA
            * in this port.
            */
            pvAttr       = NULL;
            ulAttrLength = 0;
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (((pxTemplate[iAttrib].type == CKA_MODULUS_BITS) && (sss_object.cipherType != kSSS_CipherType_RSA_CRT &&
                                                                       sss_object.cipherType != kSSS_CipherType_RSA)) ||
                ((pxTemplate[iAttrib].type == CKA_PRIME_BITS) && sss_object.cipherType != kSSS_CipherType_EC_NIST_P)) {
                xResult = CKR_ARGUMENTS_BAD;
                break;
            }
            xResult = pkcs11_read_object_size(xObject, &outKeyIndex);
            if (xResult != CKR_OK) {
                break;
            }
            size         = (size_t)outKeyIndex * 8;
            pvAttr       = (void *)&size;
            ulAttrLength = sizeof(size_t);
            break;
        }
        case CKA_VENDOR_DEFINED: {
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_MODULUS: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            // CKA_MODULUS is only valid for RSA Key. Issue triggered by OpenSSH7.6(SIMW-2669)
            if ((sss_object.cipherType != kSSS_CipherType_RSA) && (sss_object.cipherType != kSSS_CipherType_RSA_CRT)) {
                LOG_W("Object %08X cipher type is not RSA.", (unsigned int)sss_object.keyId);
                ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                xResult      = CKR_ARGUMENTS_BAD;
                break;
            }

            if (kStatus_SSS_Success !=
                sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            if (kStatus_SSS_Success !=
                sss_util_asn1_rsa_parse_public(&data[0], dataLen, &rsaN, &rsaNlen, &rsaE, &rsaElen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            ulAttrLength = rsaNlen;
            pvAttr       = (void *)rsaN;
            break;
        }
        case CKA_PUBLIC_EXPONENT: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            // CKA_MODULUS is only valid for RSA Key. Issue triggered by OpenSSH7.6(SIMW-2669)
            if ((sss_object.cipherType != kSSS_CipherType_RSA) && (sss_object.cipherType != kSSS_CipherType_RSA_CRT)) {
                LOG_W("Object %08X cipher type is not RSA.", (unsigned int)sss_object.keyId);
                ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                xResult      = CKR_ARGUMENTS_BAD;
                break;
            }

            if (kStatus_SSS_Success !=
                sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            if (kStatus_SSS_Success !=
                sss_util_asn1_rsa_parse_public(&data[0], dataLen, &rsaN, &rsaNlen, &rsaE, &rsaElen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            ulAttrLength = rsaElen;
            pvAttr       = (void *)rsaE;
            break;
        }
        case CKA_EC_PARAMS: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            if (sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
#if SSS_HAVE_SE05X_VER_GTE_07_02
                if (SM_OK != Se05x_API_ReadObjectAttributes(&se05x_session->s_ctx, sss_object.keyId, data, &dataLen)) {
                    pvAttr       = NULL;
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                /* Getting the SecObjType from attributes */
                ObjType = data[4];
                tag     = ASN_TAG_OBJ_IDF;

                switch (ObjType) {
                case kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P192:
                case kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P192:
                case kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P192:
                    memcpy(
                        &ecParam[2], (uint8_t *)MBEDTLS_OID_EC_GRP_SECP192R1, sizeof(MBEDTLS_OID_EC_GRP_SECP192R1) - 1);
                    ecParam[0]   = tag;
                    ecParam[1]   = sizeof(MBEDTLS_OID_EC_GRP_SECP192R1) - 1;
                    ulAttrLength = sizeof(MBEDTLS_OID_EC_GRP_SECP192R1) + 1;
                    pvAttr       = &ecParam[0];
                    break;
                case kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P224:
                case kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P224:
                case kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P224:
                    memcpy(
                        &ecParam[2], (uint8_t *)MBEDTLS_OID_EC_GRP_SECP224R1, sizeof(MBEDTLS_OID_EC_GRP_SECP224R1) - 1);
                    ecParam[0]   = tag;
                    ecParam[1]   = sizeof(MBEDTLS_OID_EC_GRP_SECP224R1) - 1;
                    ulAttrLength = sizeof(MBEDTLS_OID_EC_GRP_SECP224R1) + 1;
                    pvAttr       = &ecParam[0];
                    break;
                case kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P256:
                case kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P256:
                case kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P256:
                    memcpy(
                        &ecParam[2], (uint8_t *)MBEDTLS_OID_EC_GRP_SECP256R1, sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) - 1);
                    ecParam[0]   = tag;
                    ecParam[1]   = sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) - 1;
                    ulAttrLength = sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) + 1;
                    pvAttr       = &ecParam[0];
                    break;
                case kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P384:
                case kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P384:
                case kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P384:
                    memcpy(
                        &ecParam[2], (uint8_t *)MBEDTLS_OID_EC_GRP_SECP384R1, sizeof(MBEDTLS_OID_EC_GRP_SECP384R1) - 1);
                    ecParam[0]   = tag;
                    ecParam[1]   = sizeof(MBEDTLS_OID_EC_GRP_SECP384R1) - 1;
                    ulAttrLength = sizeof(MBEDTLS_OID_EC_GRP_SECP384R1) + 1;
                    pvAttr       = &ecParam[0];
                    break;
                case kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P521:
                case kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P521:
                case kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P521:
                    memcpy(
                        &ecParam[2], (uint8_t *)MBEDTLS_OID_EC_GRP_SECP521R1, sizeof(MBEDTLS_OID_EC_GRP_SECP521R1) - 1);
                    ecParam[0]   = tag;
                    ecParam[1]   = sizeof(MBEDTLS_OID_EC_GRP_SECP521R1) - 1;
                    ulAttrLength = sizeof(MBEDTLS_OID_EC_GRP_SECP521R1) + 1;
                    pvAttr       = &ecParam[0];
                    break;
                default:
                    if (kStatus_SSS_Success !=
                        sss_key_store_get_key(
                            &pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                        ulAttrLength = 0;
                        xResult      = CKR_FUNCTION_FAILED;
                        break;
                    }
                    xResult      = pkcs11_ecPublickeyGetEcParams(&data[0], &dataLen);
                    ulAttrLength = dataLen;
                    pvAttr       = &data[0];
                    break;
                }
#else
                LOG_E("Curve type not supported hence unable to get EC Params");
                pvAttr       = NULL;
                ulAttrLength = 0;
                xResult      = CKR_DEVICE_ERROR;

#endif //SSS_HAVE_SE05X_VER_GTE_07_02
            }
            else {
                if (kStatus_SSS_Success !=
                    sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                xResult      = pkcs11_ecPublickeyGetEcParams(&data[0], &dataLen);
                ulAttrLength = dataLen;
                pvAttr       = &data[0];
            }

            break;
        }
        case CKA_EC_POINT: {
            KeyBitLen = 256;
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            if (kStatus_SSS_Success !=
                sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            if (kStatus_SSS_Success !=
                sss_util_pkcs8_asn1_get_ec_public_key_index(&data[0], dataLen, &outKeyIndex, &pubKeyLen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (pubKeyLen <= 127) {
                if (outKeyIndex < 1) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                outKeyIndex       = outKeyIndex - 1;
                data[outKeyIndex] = pubKeyLen;
                pubKeyLen++;
            }
            else if (pubKeyLen <= 255) {
                if (outKeyIndex < 2) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                outKeyIndex           = outKeyIndex - 2;
                data[outKeyIndex]     = 0x81;
                data[outKeyIndex + 1] = pubKeyLen;
                pubKeyLen             = pubKeyLen + 2;
            }
            else {
                if (outKeyIndex < 3) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                outKeyIndex           = outKeyIndex - 3;
                data[outKeyIndex]     = 0x82;
                data[outKeyIndex + 1] = (pubKeyLen & 0x00FF00) >> 8;
                data[outKeyIndex + 2] = (pubKeyLen & 0x00FF);
                pubKeyLen             = pubKeyLen + 3;
            }

            pubKeyLen++;
            if (outKeyIndex < 1) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            outKeyIndex = outKeyIndex - 1;

            data[outKeyIndex] = ASN_TAG_OCTETSTRING;

            ulAttrLength = pubKeyLen;
            pvAttr       = &data[outKeyIndex];
            break;
        }
        case CKA_CLASS: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                if (xObject == pxSession->pAttrKey->keyPairObjHandle) {
                    /* Doing nothing as its the same object handle */
                }
                else {
                    /* Reset structure so that it can move to next object handle */
                    pxSession->pAttrKey->keyPairObjHandle = xObject;
                    pxSession->pAttrKey->xSetPublicKey    = CK_FALSE;
                    pxSession->pAttrKey->keyState         = 0;
                }

                /* Returning public/private according to the flag */
                if (pxSession->pAttrKey->xSetPublicKey != CK_TRUE) {
                    objectClass  = CKO_PRIVATE_KEY;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
                else {
                    objectClass  = CKO_PUBLIC_KEY;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }

                /* To handling the public/private object and key states correctly */
                switch (pxSession->pAttrKey->keyState) {
                case PrivateKeySize: {
                    pxSession->pAttrKey->keyState++;
                    break;
                }
                case PrivateKeyAttr: {
                    pxSession->pAttrKey->xSetPublicKey = CK_TRUE;
                    pxSession->pAttrKey->keyState++;
                    break;
                }
                case PublicKeySize: {
                    pxSession->pAttrKey->keyState++;
                    break;
                }
                case PublicKeyAttr: {
                    pxSession->pAttrKey->xSetPublicKey = CK_FALSE;
                    pxSession->pAttrKey->keyState      = 0;
                    break;
                }
                default: {
                    LOG_E("Invalid keystate hence unable to handle keypair");
                    pvAttr       = NULL;
                    ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                    break;
                }
                }
            }
            else if (sss_object.objectType == kSSS_KeyPart_Public) {
                objectClass  = CKO_PUBLIC_KEY;
                pvAttr       = &objectClass;
                ulAttrLength = sizeof(objectClass);
            }
            else if (sss_object.objectType == kSSS_KeyPart_Default) {
                if (sss_object.cipherType == kSSS_CipherType_Binary) {
                    CK_BBOOL isX509Cert = CK_FALSE;
                    isX509Cert          = pkcs11_is_X509_certificate(sss_object.keyId);

                    if (isX509Cert == CK_TRUE) {
                        objectClass  = CKO_CERTIFICATE;
                        pvAttr       = &objectClass;
                        ulAttrLength = sizeof(objectClass);
                    }
                    else {
                        objectClass = CKO_DATA;
                        pvAttr      = &objectClass;
                        ;
                        ulAttrLength = sizeof(objectClass);
                    }
                }
                else if (sss_object.cipherType == kSSS_CipherType_Count) {
                    objectClass  = CKO_HW_FEATURE;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
                else if ((sss_object.cipherType == kSSS_CipherType_UserID) ||
                         (sss_object.cipherType == kSSS_CipherType_PCR)) {
                    objectClass  = CKO_DATA;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
                else {
                    objectClass  = CKO_SECRET_KEY;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
            }
            else {
                ulAttrLength    = CK_UNAVAILABLE_INFORMATION;
                xResult         = CKR_ATTRIBUTE_SENSITIVE;
                infoUnavailable = CK_TRUE;
            }
            break;
        }
        case CKA_HW_FEATURE_TYPE: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if ((sss_object.objectType == kSSS_KeyPart_Default) && (sss_object.cipherType == kSSS_CipherType_Count)) {
                hwFeatureType = CKH_MONOTONIC_COUNTER;
                pvAttr        = &hwFeatureType;
                ulAttrLength  = sizeof(hwFeatureType);
            }
            else {
                ulAttrLength    = CK_UNAVAILABLE_INFORMATION;
                xResult         = CKR_ATTRIBUTE_SENSITIVE;
                infoUnavailable = CK_TRUE;
            }
            break;
        }
        case CKA_ENCRYPT: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (sss_object.objectType == kSSS_KeyPart_Public) {
                if (sss_object.cipherType == kSSS_CipherType_RSA_CRT || sss_object.cipherType == kSSS_CipherType_RSA) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else if (sss_object.objectType == kSSS_KeyPart_Default) {
                if (sss_object.cipherType == kSSS_CipherType_AES) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else {
                supported    = CK_FALSE;
                pvAttr       = &supported;
                ulAttrLength = sizeof(supported);
            }
            break;
        }
        case CKA_DECRYPT: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                if (sss_object.cipherType == kSSS_CipherType_RSA_CRT || sss_object.cipherType == kSSS_CipherType_RSA) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else if (sss_object.objectType == kSSS_KeyPart_Default) {
                if (sss_object.cipherType == kSSS_CipherType_AES) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else {
                supported    = CK_FALSE;
                pvAttr       = &supported;
                ulAttrLength = sizeof(supported);
            }
            break;
        }
        case CKA_SIGN: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                if (sss_object.cipherType == kSSS_CipherType_RSA_CRT || sss_object.cipherType == kSSS_CipherType_RSA ||
                    sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else {
                supported    = CK_FALSE;
                pvAttr       = &supported;
                ulAttrLength = sizeof(supported);
            }
            break;
        }
        case CKA_VERIFY: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (sss_object.objectType == kSSS_KeyPart_Public) {
                if (sss_object.cipherType == kSSS_CipherType_RSA_CRT || sss_object.cipherType == kSSS_CipherType_RSA ||
                    sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else {
                supported    = CK_FALSE;
                pvAttr       = &supported;
                ulAttrLength = sizeof(supported);
            }
            break;
        }
        case CKA_WRAP:
        case CKA_UNWRAP:
        case CKA_SIGN_RECOVER:
        case CKA_VERIFY_RECOVER: {
            supported    = CK_FALSE;
            ulAttrLength = sizeof(supported);
            pvAttr       = &(supported);
            break;
        }
        case CKA_DERIVE: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (sss_object.objectType == kSSS_KeyPart_Pair && sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
                supported    = CK_TRUE;
                ulAttrLength = sizeof(supported);
                pvAttr       = &(supported);
            }
            else {
                supported    = CK_FALSE;
                ulAttrLength = sizeof(supported);
                pvAttr       = &(supported);
            }
            break;
        }
        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
        case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
        case CKA_SUBJECT: {
            ulAttrLength = sizeof(data);
            if (xObject > UINT32_MAX) {
                pvAttr       = NULL;
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            xResult = pkcs11_parse_certificate_get_attribute(
                (uint32_t)xObject, pxTemplate[iAttrib].type, &data[0], &ulAttrLength);
            if (xResult != CKR_OK) {
                pvAttr       = NULL;
                ulAttrLength = 0;
            }
            else {
                pvAttr = &data[0];
            }
            break;
        }
        case CKA_OPENSC_NON_REPUDIATION_0_17:
        case CKA_OPENSC_NON_REPUDIATION_0_21: {
            // Not support NON-REPUDIATION signature
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_SENSITIVE:
        case CKA_ALWAYS_SENSITIVE: {
            supported = CK_FALSE;

            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                // Private key
                supported = CK_TRUE;
            }
            else if (sss_object.objectType == kSSS_KeyPart_Default) {
                if ((sss_object.cipherType != kSSS_CipherType_Binary) &&
                    (sss_object.cipherType != kSSS_CipherType_Count)) {
                    // Secret key
                    supported = CK_TRUE;
                }
            }

            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_EXTRACTABLE: {
            supported = CK_TRUE;

            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

#if SSS_HAVE_SE05X_VER_GTE_06_00
            // Get attribute
            if (SM_OK != Se05x_API_ReadObjectAttributes(&se05x_session->s_ctx, sss_object.keyId, data, &dataLen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (kStatus_SSS_Success != pkcs11_parse_atrribute(&obj_attr,
                                           data,
                                           dataLen,
                                           sss_object.objectType,
                                           sss_object.cipherType,
                                           POLICY_OBJ_ALLOW_IMPORT_EXPORT,
                                           &supported)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

#else
            // SE050 doesn't support ReadObjectAttributes, so use pre-defined value according to key type.
            supported = CK_TRUE;
            if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                // Private key
                supported = CK_FALSE;
            }
            else if (sss_object.objectType == kSSS_KeyPart_Default) {
                if ((sss_object.cipherType != kSSS_CipherType_Binary) &&
                    (sss_object.cipherType != kSSS_CipherType_Count)) {
                    // Secret key
                    supported = CK_FALSE;
                }
            }
#endif /* SSS_HAVE_SE05X_VER_GTE_06_00 */
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_NEVER_EXTRACTABLE: {
            // Not NEVER_EXTRACTABLE
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_LOCAL: {
#if SSS_HAVE_SE05X_VER_GTE_06_00
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            // Get attribute
            if (SM_OK != Se05x_API_ReadObjectAttributes(&se05x_session->s_ctx, sss_object.keyId, data, &dataLen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            // Parse attribute for Origin value
            if (kStatus_SSS_Success !=
                pkcs11_parse_atrribute(
                    &obj_attr, data, dataLen, sss_object.objectType, sss_object.cipherType, 0, NULL)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (obj_attr.origin == kSE05x_Origin_INTERNAL) {
                supported = CK_TRUE;
            }
            else {
                supported = CK_FALSE;
            }
#else
            // SE050 doesn't support ReadObjectAttributes, so use pre-defined value.
            supported = CK_FALSE;
#endif /* SSS_HAVE_SE05X_VER_GTE_06_00 */
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_ALLOWED_MECHANISMS: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            switch (sss_object.cipherType) {
            case kSSS_CipherType_RSA:
            case kSSS_CipherType_RSA_CRT:
                pvAttr       = (void *)rsa_mechanisms;
                ulAttrLength = sizeof(rsa_mechanisms);

                break;
            case kSSS_CipherType_EC_NIST_P:
            case kSSS_CipherType_EC_BRAINPOOL:
            case kSSS_CipherType_EC_NIST_K:
            case kSSS_CipherType_EC_TWISTED_ED:
            case kSSS_CipherType_EC_MONTGOMERY:
            case kSSS_CipherType_EC_BARRETO_NAEHRIG:
                pvAttr       = (void *)ecc_mechanisms;
                ulAttrLength = sizeof(ecc_mechanisms);

                break;
            case kSSS_CipherType_AES:
                pvAttr       = (void *)aes_mechanisms;
                ulAttrLength = sizeof(aes_mechanisms);

                break;
            case kSSS_CipherType_DES:
                pvAttr       = (void *)des_mechanisms;
                ulAttrLength = sizeof(des_mechanisms);

                break;
            default:
                ulAttrLength = 0;
                xResult      = CKR_ARGUMENTS_BAD;
                break;
            }
            break;
        }
        case CKA_APPLICATION:
        case CKA_OBJECT_ID: {
            // CKA_APPLICATION: Description of the application that manages the object (default empty)
            // CKA_VALUE: DER-encoding of the object identifier indicating the data object type (default empty)
            pvAttr       = NULL;
            ulAttrLength = 0;
            break;
        }
        case CKA_MODIFIABLE: {
            supported = CK_TRUE;
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

#if SSS_HAVE_SE05X_VER_GTE_06_00
            // Get attribute
            if (SM_OK != Se05x_API_ReadObjectAttributes(&se05x_session->s_ctx, sss_object.keyId, data, &dataLen)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            if (kStatus_SSS_Success != pkcs11_parse_atrribute(&obj_attr,
                                           data,
                                           dataLen,
                                           sss_object.objectType,
                                           sss_object.cipherType,
                                           POLICY_OBJ_ALLOW_WRITE,
                                           &supported)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

#else
            // SE050 doesn't support ReadObjectAttributes, so use pre-defined value.
            supported = CK_TRUE;
#endif /* SSS_HAVE_SE05X_VER_GTE_06_00 */
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_PRIVATE: {
            // When the CKA_PRIVATE attribute is CK_TRUE, a user may not access the object until
            // the user has been authenticated to the token.
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        default: {
            LOG_W("Attribute required : 0x%08lx\n", pxTemplate[iAttrib].type);
            ulAttrLength    = CK_UNAVAILABLE_INFORMATION;
            infoUnavailable = CK_TRUE;
            xResult         = CKR_ATTRIBUTE_SENSITIVE;
            break;
        }
        }

        if (CKR_OK == xResult) {
            /*
            * Copy out the data and size.
            */

            if (NULL != pxTemplate[iAttrib].pValue && !infoUnavailable && (NULL != pvAttr)) {
                if (pxTemplate[iAttrib].ulValueLen < ulAttrLength) {
                    xResult      = CKR_BUFFER_TOO_SMALL;
                    ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                }
                else {
                    memcpy(pxTemplate[iAttrib].pValue, pvAttr, ulAttrLength);
                }
            }
        }
        pxTemplate[iAttrib].ulValueLen = ulAttrLength;
        if (rsaN) {
            SSS_FREE(rsaN);
        }
        if (rsaE) {
            SSS_FREE(rsaE);
        }
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

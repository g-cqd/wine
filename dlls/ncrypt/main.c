/*
 * New cryptographic library (ncrypt.dll)
 *
 * Copyright 2016 Alex Henrie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "ncrypt.h"
#include "bcrypt.h"
#include "ncrypt_internal.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ncrypt);

static SECURITY_STATUS map_ntstatus(NTSTATUS status)
{
    switch (status)
    {
    case STATUS_INVALID_HANDLE:    return NTE_INVALID_HANDLE;
    case STATUS_INVALID_SIGNATURE: return NTE_BAD_SIGNATURE;
    case STATUS_SUCCESS:           return ERROR_SUCCESS;
    case STATUS_INVALID_PARAMETER: return NTE_INVALID_PARAMETER;
    case STATUS_NO_MEMORY:         return NTE_NO_MEMORY;
    case STATUS_NOT_SUPPORTED:     return NTE_NOT_SUPPORTED;
    case NTE_BAD_DATA:             return NTE_BAD_DATA;
    case STATUS_BUFFER_TOO_SMALL:  return NTE_BUFFER_TOO_SMALL;
    default:
        FIXME("unhandled status %#lx\n", status);
        return NTE_INTERNAL_ERROR;
    }
}

static struct object *allocate_object(enum object_type type)
{
    struct object *ret;
    if (!(ret = calloc(1, sizeof(*ret)))) return NULL;
    ret->type = type;
    return ret;
}

static struct object_property *get_object_property(struct object *object, const WCHAR *name)
{
    unsigned int i;
    for (i = 0; i < object->num_properties; i++)
    {
        struct object_property *property = &object->properties[i];
        if (!lstrcmpW(property->key, name)) return property;
    }
    return NULL;
}

struct object_property *add_object_property(struct object *object, const WCHAR *name)
{
    struct object_property *property;

    if (!object->num_properties)
    {
        if (!(object->properties = malloc(sizeof(*property))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        property = &object->properties[object->num_properties++];
    }
    else
    {
        struct object_property *tmp;
        if (!(tmp = realloc(object->properties, sizeof(*property) * (object->num_properties + 1))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        object->properties = tmp;
        property = &object->properties[object->num_properties++];
    }

    memset(property, 0, sizeof(*property));
    if (!(property->key = wcsdup(name)))
    {
        ERR("Error allocating memory.\n");
        return NULL;
    }

    return property;
}

static SECURITY_STATUS set_object_property(struct object *object, const WCHAR *name, BYTE *value, DWORD value_size)
{
    struct object_property *property = get_object_property(object, name);
    void *tmp;

    if (!property && !(property = add_object_property(object, name))) return NTE_NO_MEMORY;

    if (!(tmp = realloc(property->value, max(1, value_size))))
    {
        ERR("Error allocating memory.\n");
        return NTE_NO_MEMORY;
    }

    property->value = tmp;
    property->value_size = value_size;
    memcpy(property->value, value, value_size);

    return ERROR_SUCCESS;
}

struct ecc_alg
{
    const WCHAR *name;
    const WCHAR *group;
    BCRYPT_ALG_HANDLE handle;
    DWORD bits;
};

static const struct ecc_alg ecc_algs[] =
{
    { BCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_ECDSA_ALGORITHM_GROUP, BCRYPT_ECDSA_P256_ALG_HANDLE, 256 },
    { BCRYPT_ECDSA_P384_ALGORITHM, NCRYPT_ECDSA_ALGORITHM_GROUP, BCRYPT_ECDSA_P384_ALG_HANDLE, 384 },
    { BCRYPT_ECDSA_P521_ALGORITHM, NCRYPT_ECDSA_ALGORITHM_GROUP, BCRYPT_ECDSA_P521_ALG_HANDLE, 521 },
    { BCRYPT_ECDH_P256_ALGORITHM,  NCRYPT_ECDH_ALGORITHM_GROUP,  BCRYPT_ECDH_P256_ALG_HANDLE,  256 },
    { BCRYPT_ECDH_P384_ALGORITHM,  NCRYPT_ECDH_ALGORITHM_GROUP,  BCRYPT_ECDH_P384_ALG_HANDLE,  384 },
    { BCRYPT_ECDH_P521_ALGORITHM,  NCRYPT_ECDH_ALGORITHM_GROUP,  BCRYPT_ECDH_P521_ALG_HANDLE,  521 },
};

static const struct ecc_alg *find_ecc_alg(const WCHAR *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ecc_algs); i++) if (!lstrcmpiW(name, ecc_algs[i].name)) return &ecc_algs[i];
    return NULL;
}

static struct object *create_key_object(enum algid algid, NCRYPT_PROV_HANDLE provider)
{
    NCRYPT_SUPPORTED_LENGTHS supported_lengths = {512, 16384, 8, 1024};
    struct object *object;
    DWORD dw_value;

    switch (algid)
    {
    case RSA:
        if (!(object = allocate_object(KEY))) return NULL;

        object->key.algid = RSA;
        set_object_property(object, NCRYPT_ALGORITHM_PROPERTY, (BYTE *)BCRYPT_RSA_ALGORITHM,
                            sizeof(BCRYPT_RSA_ALGORITHM));
        set_object_property(object, NCRYPT_ALGORITHM_GROUP_PROPERTY, (BYTE *)BCRYPT_RSA_ALGORITHM,
                            sizeof(BCRYPT_RSA_ALGORITHM));
        set_object_property(object, NCRYPT_LENGTHS_PROPERTY, (BYTE *)&supported_lengths,
                            sizeof(supported_lengths));
        dw_value = 128;
        set_object_property(object, NCRYPT_BLOCK_LENGTH_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value));
        dw_value = 128;
        set_object_property(object, BCRYPT_SIGNATURE_LENGTH, (BYTE *)&dw_value, sizeof(dw_value));
        break;

    case ECDSA:
        if (!(object = allocate_object(KEY))) return NULL;
        object->key.algid = ECDSA;
        break;

    default:
        ERR("Invalid algid %#x\n", algid);
        return NULL;
    }

    dw_value = 0;
    set_object_property(object, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value));
    dw_value = NCRYPT_ALLOW_ALL_USAGES;
    set_object_property(object, NCRYPT_KEY_USAGE_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value));
    dw_value = 0;
    set_object_property(object, NCRYPT_KEY_TYPE_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value));
    set_object_property(object, NCRYPT_PROVIDER_HANDLE_PROPERTY, (BYTE *)&provider, sizeof(provider));
    return object;
}

static void free_partial_key_object(struct object *object);

static void set_ecc_properties(struct object *object, const struct ecc_alg *ecc)
{
    NCRYPT_SUPPORTED_LENGTHS lengths = {ecc->bits, ecc->bits, 0, ecc->bits};
    DWORD sig_len = 2 * ((ecc->bits + 7) / 8);

    object->key.ecc = ecc;
    set_object_property(object, NCRYPT_ALGORITHM_PROPERTY, (BYTE *)ecc->name, (lstrlenW(ecc->name) + 1) * sizeof(WCHAR));
    set_object_property(object, NCRYPT_ALGORITHM_GROUP_PROPERTY, (BYTE *)ecc->group,
                        (lstrlenW(ecc->group) + 1) * sizeof(WCHAR));
    set_object_property(object, NCRYPT_LENGTHS_PROPERTY, (BYTE *)&lengths, sizeof(lengths));
    set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&ecc->bits, sizeof(ecc->bits));
    set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&ecc->bits, sizeof(ecc->bits));
    set_object_property(object, BCRYPT_SIGNATURE_LENGTH, (BYTE *)&sig_len, sizeof(sig_len));
}

/* Persisted keys are kept in the registry, one REG_BINARY value per key name: a DWORD index into
 * ecc_algs (or ~0u for RSA) followed by the private key blob. Windows protects the blob with DPAPI;
 * here it is protected only by the access rights of the registry, like Wine's crypt32 key store. */
static const WCHAR keys_path[] = L"Software\\Wine\\NCrypt\\Keys";
#define PERSISTED_RSA ~0u

static HKEY open_keys_root(BOOL machine, BOOL create)
{
    HKEY root = machine ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, hkey;
    LSTATUS ret = create ? RegCreateKeyExW(root, keys_path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkey, NULL)
                         : RegOpenKeyExW(root, keys_path, 0, KEY_ALL_ACCESS, &hkey);
    return ret ? NULL : hkey;
}

static BOOL persisted_key_exists(const WCHAR *name, BOOL machine)
{
    HKEY hkey = open_keys_root(machine, FALSE);
    BOOL ret;

    if (!hkey) return FALSE;
    ret = !RegQueryValueExW(hkey, name, NULL, NULL, NULL, NULL);
    RegCloseKey(hkey);
    return ret;
}

static SECURITY_STATUS persist_key(struct key *key)
{
    const WCHAR *type = key->ecc ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;
    DWORD index = key->ecc ? key->ecc - ecc_algs : PERSISTED_RSA, size;
    SECURITY_STATUS ret;
    NTSTATUS status;
    BYTE *data;
    HKEY hkey;

    if ((status = BCryptExportKey(key->bcrypt_key, NULL, type, NULL, 0, &size, 0))) return map_ntstatus(status);
    if (!(data = malloc(sizeof(index) + size))) return NTE_NO_MEMORY;
    memcpy(data, &index, sizeof(index));
    if ((status = BCryptExportKey(key->bcrypt_key, NULL, type, data + sizeof(index), size, &size, 0)))
    {
        free(data);
        return map_ntstatus(status);
    }
    if (!(hkey = open_keys_root(key->machine, TRUE))) ret = NTE_PERM;
    else
    {
        ret = RegSetValueExW(hkey, key->name, 0, REG_BINARY, data, sizeof(index) + size) ? NTE_PERM : ERROR_SUCCESS;
        RegCloseKey(hkey);
    }
    SecureZeroMemory(data, sizeof(index) + size);
    free(data);
    return ret;
}

SECURITY_STATUS WINAPI NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                                const WCHAR *algid, const WCHAR *name, DWORD keyspec, DWORD flags)
{
    const struct ecc_alg *ecc;
    struct object *object;

    TRACE("(%#Ix, %p, %s, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(algid),
          wine_dbgstr_w(name), keyspec, flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (name && !(flags & NCRYPT_OVERWRITE_KEY_FLAG) && persisted_key_exists(name, !!(flags & NCRYPT_MACHINE_KEY_FLAG)))
        return NTE_EXISTS;

    if ((ecc = find_ecc_alg(algid)))
    {
        NTSTATUS status;

        if (!(object = create_key_object(ECDSA, provider))) return NTE_NO_MEMORY;
        set_ecc_properties(object, ecc);
        if ((status = BCryptGenerateKeyPair(ecc->handle, &object->key.bcrypt_key, ecc->bits, 0)))
        {
            ERR("Error generating key pair %#lx\n", status);
            free_partial_key_object(object);
            return map_ntstatus(status);
        }
    }
    else if (!lstrcmpiW(algid, BCRYPT_RSA_ALGORITHM))
    {
        NTSTATUS status;
        DWORD default_bitlen = 1024;

        if (!(object = create_key_object(RSA, provider)))
        {
            ERR("Error allocating memory\n");
            return NTE_NO_MEMORY;
        }

        status = BCryptGenerateKeyPair(BCRYPT_RSA_ALG_HANDLE, &object->key.bcrypt_key, default_bitlen, 0);
        if (status != STATUS_SUCCESS)
        {
            ERR("Error generating key pair %#lx\n", status);
            free(object);
            return map_ntstatus(status);
        }

        set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&default_bitlen, sizeof(default_bitlen));
        set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&default_bitlen, sizeof(default_bitlen));
    }
    else
    {
        FIXME("Algorithm not handled %s\n", wine_dbgstr_w(algid));
        return NTE_NOT_SUPPORTED;
    }

    if (name)
    {
        if (!(object->key.name = wcsdup(name)))
        {
            NCryptFreeObject((NCRYPT_HANDLE)object);
            return NTE_NO_MEMORY;
        }
        object->key.machine = !!(flags & NCRYPT_MACHINE_KEY_FLAG);
    }
    *key = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptDecrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    FIXME("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx): stub\n", key, input, insize, padding,
          output, outsize, result, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptDeleteKey(NCRYPT_KEY_HANDLE key, DWORD flags)
{
    struct object *object = (struct object *)key;
    HKEY hkey;

    TRACE("(%#Ix, %#lx)\n", key, flags);

    if (!object || object->type != KEY) return NTE_INVALID_HANDLE;
    if (object->key.name && (hkey = open_keys_root(object->key.machine, FALSE)))
    {
        RegDeleteValueW(hkey, object->key.name);
        RegCloseKey(hkey);
    }
    return NCryptFreeObject(key);
}

SECURITY_STATUS WINAPI NCryptEncrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *key_object = (struct object *)key;

    TRACE("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx)\n", key, input, insize, padding,
          output, outsize, result, flags);

    if (flags & ~(NCRYPT_NO_PADDING_FLAG | NCRYPT_PAD_OAEP_FLAG
                | NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG))
    {
        FIXME("Flags %lx not supported\n", flags);
        return NTE_BAD_FLAGS;
    }

    if (flags & NCRYPT_NO_PADDING_FLAG || flags & NCRYPT_PAD_OAEP_FLAG)
    {
        FIXME("No padding and oaep padding not supported\n");
        return NTE_NOT_SUPPORTED;
    }

    if (key_object->type != KEY) return NTE_INVALID_HANDLE;

    return map_ntstatus(BCryptEncrypt(key_object->key.bcrypt_key, input, insize, padding,
                                      NULL, 0, output, outsize, result, flags));
}

SECURITY_STATUS WINAPI NCryptEnumAlgorithms(NCRYPT_PROV_HANDLE provider, DWORD alg_ops,
                                            DWORD *alg_count, NCryptAlgorithmName **alg_list, DWORD flags)
{
    FIXME("(%#Ix, %#lx, %p, %p, %#lx): stub\n", provider, alg_ops, alg_count, alg_list, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptEnumKeys(NCRYPT_PROV_HANDLE provider, const WCHAR *scope,
                                      NCryptKeyName **key_name, PVOID *enum_state, DWORD flags)
{
    FIXME("(%#Ix, %p, %p, %p, %#lx): stub\n", provider, scope, key_name, enum_state, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptFinalizeKey(NCRYPT_KEY_HANDLE handle, DWORD flags)
{
    struct object *object = (struct object *)handle;
    DWORD key_length;
    struct object_property *prop;
    NTSTATUS status;

    TRACE("(%#Ix, %#lx)\n", handle, flags);

    if (!object || object->type != KEY) return NTE_INVALID_HANDLE;

    if (!object->key.ecc)  /* the length of an ECC key is fixed by its curve */
    {
        if (!(prop = get_object_property(object, NCRYPT_LENGTH_PROPERTY))) return NTE_INVALID_HANDLE;
        key_length = *(DWORD *)prop->value;
        status = BCryptSetProperty(object->key.bcrypt_key, BCRYPT_KEY_LENGTH, (UCHAR *)&key_length, sizeof(key_length), 0);
        if (status != STATUS_SUCCESS)
        {
            ERR("Error setting key length property\n");
            return map_ntstatus(status);
        }
    }

    status = BCryptFinalizeKeyPair(object->key.bcrypt_key, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error finalizing key pair\n");
        return map_ntstatus(status);
    }

    if (object->key.name) return persist_key(&object->key);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptFreeBuffer(PVOID buf)
{
    FIXME("(%p): stub\n", buf);
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS free_key_object(struct key *key)
{
    SECURITY_STATUS ret = map_ntstatus( BCryptDestroyKey(key->bcrypt_key) );

    if (!ret) free(key->name);
    return ret;
}

/* free a key object whose BCrypt key was never created */
static void free_partial_key_object(struct object *object)
{
    unsigned int i;

    for (i = 0; i < object->num_properties; i++)
    {
        free(object->properties[i].key);
        free(object->properties[i].value);
    }
    free(object->properties);
    free(object->key.name);
    free(object);
}

SECURITY_STATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE handle)
{
    struct object *object = (struct object *)handle;
    SECURITY_STATUS ret = STATUS_SUCCESS;
    unsigned int i;

    TRACE("(%#Ix)\n", handle);

    if (!object)
    {
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    switch (object->type)
    {
    case KEY:
    {
        if ((ret = free_key_object(&object->key))) return ret;
        break;
    }
    case STORAGE_PROVIDER:
        break;

    default:
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    for (i = 0; i < object->num_properties; i++)
    {
        free(object->properties[i].key);
        free(object->properties[i].value);
    }
    free(object->properties);
    free(object);
    return ret;
}

SECURITY_STATUS WINAPI NCryptGetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *output,
                                         DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *object = (struct object *)handle;
    const struct object_property *property;

    TRACE("(%#Ix, %s, %p, %lu, %p, %#lx)\n", handle, wine_dbgstr_w(name), output, outsize, result, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    if (!(property = get_object_property(object, name))) return NTE_INVALID_PARAMETER;

    *result = property->value_size;
    if (!output) return ERROR_SUCCESS;
    if (outsize < property->value_size) return NTE_BUFFER_TOO_SMALL;

    memcpy(output, property->value, property->value_size);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptImportKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE decrypt_key,
                                       const WCHAR *type, NCryptBufferDesc *params, NCRYPT_KEY_HANDLE *handle,
                                       BYTE *data, DWORD datasize, DWORD flags)
{
    BCRYPT_KEY_BLOB *header = (BCRYPT_KEY_BLOB *)data;
    struct object *object;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %p, %lu, %#lx)\n", provider, decrypt_key, wine_dbgstr_w(type),
          params, handle, data, datasize, flags);

    if (decrypt_key)
    {
        FIXME("Key blob decryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params)
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }

    switch(header->Magic)
    {
    case BCRYPT_RSAFULLPRIVATE_MAGIC:
    case BCRYPT_RSAPRIVATE_MAGIC:
    case BCRYPT_RSAPUBLIC_MAGIC:
    {
        NTSTATUS status;
        BCRYPT_RSAKEY_BLOB *rsablob = (BCRYPT_RSAKEY_BLOB *)data;

        if (!(object = create_key_object(RSA, provider)))
        {
            ERR("Error allocating memory\n");
            return NTE_NO_MEMORY;
        }

        status = BCryptImportKeyPair(BCRYPT_RSA_ALG_HANDLE, NULL, type, &object->key.bcrypt_key, data, datasize, 0);
        if (status != STATUS_SUCCESS)
        {
            WARN("Error importing key pair %#lx\n", status);
            free(object);
            return map_ntstatus(status);
        }

        set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&rsablob->BitLength, sizeof(rsablob->BitLength));
        set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&rsablob->BitLength, sizeof(rsablob->BitLength));
        break;
    }
    default:
        FIXME("Unhandled key magic %#lx\n", header->Magic);
        return NTE_INVALID_PARAMETER;
    }

    *handle = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptExportKey(NCRYPT_KEY_HANDLE key, NCRYPT_KEY_HANDLE encrypt_key, const WCHAR *type,
                                       NCryptBufferDesc *params, BYTE *output, DWORD output_len, DWORD *ret_len,
                                       DWORD flags)
{
    struct object *object = (struct object *)key;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %lu, %p, %#lx)\n", key, encrypt_key, wine_dbgstr_w(type), params, output,
          output_len, ret_len, flags);

    if (encrypt_key)
    {
        FIXME("Key blob encryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params)
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }

    return map_ntstatus(BCryptExportKey(object->key.bcrypt_key, NULL, type, output, output_len, ret_len, 0));
}

SECURITY_STATUS WINAPI NCryptIsAlgSupported(NCRYPT_PROV_HANDLE provider, const WCHAR *algid, DWORD flags)
{
    static const ULONG supported = BCRYPT_CIPHER_OPERATION |\
                                   BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |\
                                   BCRYPT_SIGNATURE_OPERATION |\
                                   BCRYPT_SECRET_AGREEMENT_OPERATION;
    BCRYPT_ALGORITHM_IDENTIFIER *list;
    ULONG i, count;
    NTSTATUS status;

    TRACE("(%#Ix, %s, %#lx)\n", provider, wine_dbgstr_w(algid), flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!lstrcmpiW(BCRYPT_RSA_SIGN_ALGORITHM, algid)) return NTE_NOT_SUPPORTED;

    status = BCryptEnumAlgorithms(supported, &count, &list, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error retrieving algorithm list %#lx\n", status);
        return map_ntstatus(status);
    }

    status = STATUS_NOT_SUPPORTED;
    for (i = 0; i < count; i++)
    {
        if (!lstrcmpiW(list[i].pszName, algid))
        {
            status = STATUS_SUCCESS;
            break;
        }
    }

    BCryptFreeBuffer(list);
    return map_ntstatus(status);
}

BOOL WINAPI NCryptIsKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    FIXME("(%#Ix): stub\n", hKey);
    return FALSE;
}

SECURITY_STATUS WINAPI NCryptOpenKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                     const WCHAR *name, DWORD keyspec, DWORD flags)
{
    BOOL machine = !!(flags & NCRYPT_MACHINE_KEY_FLAG);
    DWORD type, size = 0, index;
    struct object *object;
    NTSTATUS status;
    BYTE *data;
    HKEY hkey;

    TRACE("(%#Ix, %p, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(name), keyspec, flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!key || !name) return NTE_INVALID_PARAMETER;
    if (!(hkey = open_keys_root(machine, FALSE))) return NTE_BAD_KEYSET;
    if (RegQueryValueExW(hkey, name, NULL, &type, NULL, &size) || type != REG_BINARY || size <= sizeof(index))
    {
        RegCloseKey(hkey);
        return NTE_BAD_KEYSET;
    }
    if (!(data = malloc(size)))
    {
        RegCloseKey(hkey);
        return NTE_NO_MEMORY;
    }
    if (RegQueryValueExW(hkey, name, NULL, NULL, data, &size)) size = 0;
    RegCloseKey(hkey);
    if (size <= sizeof(index))
    {
        free(data);
        return NTE_BAD_KEYSET;
    }
    memcpy(&index, data, sizeof(index));

    if (index == PERSISTED_RSA)
    {
        BCRYPT_RSAKEY_BLOB *blob = (BCRYPT_RSAKEY_BLOB *)(data + sizeof(index));

        if (size - sizeof(index) < sizeof(*blob) || !(object = create_key_object(RSA, provider))) goto bad;
        status = BCryptImportKeyPair(BCRYPT_RSA_ALG_HANDLE, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, &object->key.bcrypt_key,
                                     data + sizeof(index), size - sizeof(index), 0);
        set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&blob->BitLength, sizeof(blob->BitLength));
        set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&blob->BitLength, sizeof(blob->BitLength));
    }
    else if (index < ARRAY_SIZE(ecc_algs))
    {
        if (!(object = create_key_object(ECDSA, provider))) goto bad;
        set_ecc_properties(object, &ecc_algs[index]);
        status = BCryptImportKeyPair(ecc_algs[index].handle, NULL, BCRYPT_ECCPRIVATE_BLOB, &object->key.bcrypt_key,
                                     data + sizeof(index), size - sizeof(index), 0);
    }
    else goto bad;

    SecureZeroMemory(data, size);
    free(data);
    if (status)
    {
        WARN("Error importing persisted key %s: %#lx\n", wine_dbgstr_w(name), status);
        free_partial_key_object(object);
        return map_ntstatus(status);
    }
    if (!(object->key.name = wcsdup(name)))
    {
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return NTE_NO_MEMORY;
    }
    object->key.machine = machine;
    *key = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;

bad:
    WARN("Unreadable persisted key %s\n", wine_dbgstr_w(name));
    SecureZeroMemory(data, size);
    free(data);
    return NTE_BAD_KEYSET;
}

SECURITY_STATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *provider, const WCHAR *name, DWORD flags)
{
    struct object *object;

    FIXME("(%p, %s, %#lx): stub\n", provider, wine_dbgstr_w(name), flags);

    if (!(object = allocate_object(STORAGE_PROVIDER)))
    {
        ERR("Error allocating memory.\n");
        return NTE_NO_MEMORY;
    }
    *provider = (NCRYPT_PROV_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptSetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *input, DWORD insize, DWORD flags)
{
    struct object *object = (struct object *)handle;

    TRACE("(%#Ix, %s, %p, %lu, %#lx)\n", handle, wine_dbgstr_w(name), input, insize, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    return set_object_property(object, name, input, insize);
}

SECURITY_STATUS WINAPI NCryptSignHash(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *value, DWORD value_len,
                                      BYTE *sig, DWORD sig_len, DWORD *ret_len, DWORD flags)
{
    struct object *object = (struct object *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, value, value_len, sig, sig_len, flags);
    if (flags & NCRYPT_SILENT_FLAG) FIXME("Silent flag not implemented\n");

    if (!object || object->type != KEY) return NTE_INVALID_HANDLE;

    return map_ntstatus(BCryptSignHash(object->key.bcrypt_key, padding, value, value_len, sig, sig_len,
                                       ret_len, flags & ~NCRYPT_SILENT_FLAG));
}

SECURITY_STATUS WINAPI NCryptVerifySignature(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *hash, DWORD hash_size,
                                             BYTE *signature, DWORD signature_size, DWORD flags)
{
    struct object *key_object = (struct object *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, hash, hash_size, signature,
          signature_size, flags);

    if (!hash_size || !signature_size) return NTE_INVALID_PARAMETER;
    if (!hash || !signature) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (!handle || key_object->type != KEY) return NTE_INVALID_HANDLE;

    if (key_object->key.algid < RSA)
    {
        FIXME("Symmetric keys not supported.\n");
        return NTE_NOT_SUPPORTED;
    }

    return map_ntstatus(BCryptVerifySignature(key_object->key.bcrypt_key, padding, hash, hash_size, signature,
                                              signature_size, flags));
}

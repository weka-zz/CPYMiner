import idautils
import idc
import idaapi
import idc

# copy_fun=['blt_str_utf8_cpy','sstrncpy','strlcpy','memcpy','strcpy','strncpy','memccpy','wcscpy',
# 'wcsncpy','wmemcpy','mempcpy','strcat','strncat','wcscat','wcsncat','memmove','wmemmove','bcopy',
# 'alps_lib_toupper','wcsxfrm']

#copy_fun=['alps_lib_toupper', 'blt_str_utf8_cpy', 'sstrncpy', 'strlcpy', 'strcpy', 'strncpy', 'memmove', 'mempcpy', 'memccpy', 'memcpy', 'wcsncpy', 'wmemcpy', 'wmemmove', 'wcsxfrm','__cpy','wcpncpy','__memcpy_chk','__strcpy_chk','__wcscpy_chk','__strcat_chk','__strncat_chk','__wcscat_chk','__wcsncat_chk','stpcpy']
copy_fun=['alps_lib_toupper', 'blt_str_utf8_cpy', 'sstrncpy', 'strlcpy', 'strcat', 'strcpy', 'strncat', 'strncpy', 'memmove', 'mempcpy', 'memccpy', 'memcpy', 'wcscat', 'wcscpy', 'wcsncat', 'wcsncpy', 'wmemcpy', 'wmemmove', 'wcsxfrm','bcopy','wmempcpy','__cpy','stpcpy','wcpncpy','__memcpy_chk','__strcpy_chk','__wcscpy_chk','__strcat_chk','__strncat_chk','__wcscat_chk','__wcsncat_chk']
funlist=[]
funs=[]
print(copy_fun)
for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    if func_name in copy_fun:
        fun='sub_'+hex(func_ea)[2:].upper()
        funlist.append(fun)
        funs.append(func_name)
print(funlist,len(funlist))
print(funs,len(funs))

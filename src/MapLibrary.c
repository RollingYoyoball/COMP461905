#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>

#include "Link.h"
#include "LoaderInternal.h"

//self added
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))

static const char *sys_path[] = {
	"/usr/lib/x86_64-linux-gnu/",
	"/lib/x86_64-linux-gnu/",
	"./test_lib/"
};

static const char *fake_so[] = {
	"libc.so.6",
	"ld-linux.so.2",
	""
};

static void setup_hash(LinkMap *l)
{
	uint32_t *hash;

	/* borrowed from dl-lookup.c:_dl_setup_hash */
	Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH_NEW]->d_un.d_ptr;
	l->l_nbuckets = *hash32++;
	Elf32_Word symbias = *hash32++;
	Elf32_Word bitmask_nwords = *hash32++;

	l->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
	l->l_gnu_shift = *hash32++;

	l->l_gnu_bitmask = (Elf64_Addr *)hash32;
	hash32 += 64 / 32 * bitmask_nwords;

	l->l_gnu_buckets = hash32;
	hash32 += l->l_nbuckets;
	l->l_gnu_chain_zero = hash32 - symbias;
}

static void fill_info(LinkMap *lib)
{
	Elf64_Dyn *dyn = lib->dyn;
	Elf64_Dyn **dyn_info = lib->dynInfo;

	while (dyn->d_tag != DT_NULL)
	{
		if ((Elf64_Xword)dyn->d_tag < DT_NUM)
			dyn_info[dyn->d_tag] = dyn;
		else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT)
			dyn_info[DT_RELACOUNT_NEW] = dyn;
		else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH)
			dyn_info[DT_GNU_HASH_NEW] = dyn;
		++dyn;
	}
#define rebase(tag)                             \
	do                                          \
	{                                           \
		if (dyn_info[tag])                          \
		dyn_info[tag]->d_un.d_ptr += lib->addr; \
	} while (0)
	rebase(DT_SYMTAB);
	rebase(DT_STRTAB);
	rebase(DT_RELA);
	rebase(DT_JMPREL);
	rebase(DT_GNU_HASH_NEW); //DT_GNU_HASH
	rebase(DT_PLTGOT);
	rebase(DT_INIT);
	rebase(DT_INIT_ARRAY);
}

char *GetLibName(char *string_table){
	int lib_len=0;
	char temp_name[100];

	for (int i=0;string_table[i]!=0;++i){
		temp_name[lib_len++]=string_table[i];
	}
	char *lib_name=(char *)malloc(lib_len+1);
	strcpy(lib_name,temp_name);
	lib_name[lib_len]=0;
	return lib_name;
}
int IsFake(const char *name){
	int len,flag;
	int name_len=strlen(name);
	for (int i=0;i<3;++i){
		len=strlen(fake_so[i]);
		if (len!=name_len)
			continue;
		flag=1;
		for (int p=0;p<len&&flag;++p)
			flag&=(fake_so[i][p]==name[p]);
		if (flag)
			return 1;
	}
	return 0;
}

void *MapLibrary(const char *libpath)
{
	/*
	 * hint:
	 * 
	 * lib = malloc(sizeof(LinkMap));
	 * 
	 * foreach segment:
	 * mmap(start_addr, segment_length, segment_prot, MAP_FILE | ..., library_fd, 
	 *      segment_offset);
	 * 
	 * lib -> addr = ...;
	 * lib -> dyn = ...;
	 * 
	 * fill_info(lib);
	 * setup_hash(lib);
	 * 
	 * return lib;
	 */

	/* Your code here */

	LinkMap *lib=malloc(sizeof(LinkMap));

	//load file into buffer
	FILE *f;
	int fsize=0;
	char *buffer;
	f=fopen(libpath,"r");
	if (f==NULL){
		printf("Error: Open library file failed!\n");
		return NULL;
	}
	fseek(f,0,SEEK_END);
	fsize=ftell(f);
	fseek(f,0,SEEK_SET);
	buffer=(char*)malloc(fsize);
	fread(buffer,1,fsize,f);
	fclose(f);

	//lib init
	lib->next=NULL;
	//check whether lib is a fake so
	lib->fake=0;
	for (int i=0;i<3;++i){
		int len=strlen(sys_path[i]);
		if (strlen(libpath)<len) 
			continue;
		int flag=1;
		for (int p=0;p<len&&flag;++p)
			flag&=(sys_path[i][p]==libpath[p]);
		if (!flag) continue;
		if (IsFake(libpath+len)){
			lib->fake=1;
			break;
		}
	}

	//get elf header
	Elf64_Ehdr *elhr=malloc(sizeof(Elf64_Ehdr));
	elhr=(Elf64_Ehdr*)buffer;

	int phdr_num=elhr->e_phnum;
	int phdr_off=elhr->e_phoff;
	int phdr_size=elhr->e_phentsize;

	//just for debug
	//printf("phdr_off = %d\n",phdr_off);
	//printf("phdr_num = %d\n",phdr_num);

	//return NULL;//debug only

	void *start_addr=NULL;
	int length,prot,flags,offset;
	int pagesize=getpagesize();
	int first=1;
	uint64_t load_offset;

	Elf64_Phdr *phdr;

	LinkMap *dependency;
	char *new_libpath;

	int fd=open(libpath,O_RDONLY);//load file
	for (int i=0;i<phdr_num;++i){//for each segment
		phdr=(Elf64_Phdr *)(buffer+phdr_off);
		phdr_off+=phdr_size;

		if (phdr->p_type==PT_DYNAMIC){
			lib->dyn=(Elf64_Dyn *)(phdr->p_vaddr+(uint64_t)(lib->addr));
		}
		if (phdr->p_type!=PT_LOAD)
			continue;

		offset=ALIGN_DOWN(phdr->p_offset,pagesize);//offset in file
		length=ALIGN_UP(phdr->p_memsz,pagesize);

		if (offset+length<phdr->p_offset+phdr->p_memsz)
			length+=pagesize;
		prot=0;
		prot|=(phdr->p_flags&PF_R)?PROT_READ:0;
		prot|=(phdr->p_flags&PF_W)?PROT_WRITE:0;
		prot|=(phdr->p_flags&PF_X)?PROT_EXEC:0;
		flags=MAP_FILE|MAP_PRIVATE;

		if (first){
			//the first segment
			length=10*pagesize;
			start_addr=mmap(NULL,length,prot,flags,fd,offset);
			lib->addr=(uint64_t)start_addr;
			first=0;
		}
		else{
			flags|=MAP_FIXED;
			load_offset=ALIGN_DOWN(phdr->p_vaddr,pagesize);
			start_addr=mmap((void *)(lib->addr+load_offset),length,prot,flags,fd,offset);
		}
	}
	fill_info(lib);
	setup_hash(lib);

	//find all the needed
	Elf64_Dyn *dyn;
	char *string_table=NULL;
	int lib_name_offset;  
	char *lib_name;
	int lib_path_len,lib_name_len;
	LinkMap *tempList[20];

	for (dyn=lib->dyn;dyn->d_tag!=DT_NULL;dyn++){
		if (dyn->d_tag==DT_STRTAB){
			string_table=(char *)dyn->d_un.d_ptr;
			break;
		}
	}
	int depd_cnt=0;
	for (dyn=lib->dyn;dyn->d_tag!=DT_NULL;dyn++){
		if (dyn->d_tag!=DT_NEEDED)
			continue;

		//get lib name
		lib_name_offset=(int)dyn->d_un.d_val;
		lib_name=GetLibName(string_table+lib_name_offset);
		lib_name_len=strlen(lib_name);

		dependency=NULL;
		char *new_lib_path;
		if (!IsFake(lib_name)){
			//don't know which system path so try them all? 
			//or just use ./test_lib/ here... so pth=2
			for (int pth=2;pth<3&&dependency==NULL;++pth){
				lib_path_len=strlen(sys_path[pth]);
				new_lib_path=(char *)malloc(lib_path_len+lib_name_len+1);

				memcpy(new_lib_path,sys_path[pth],sizeof(char)*lib_path_len);
				memcpy(new_lib_path+lib_path_len,lib_name,sizeof(char)*lib_name_len);
				new_lib_path[lib_path_len+lib_name_len]=0;

				dependency=MapLibrary(new_lib_path);
			}
		}
		else{
			dependency=malloc(sizeof(LinkMap));
			dependency->fake=1;
		}
		dependency->name=lib_name;

		//add dependency to search list
		tempList[depd_cnt++]=dependency;
	}
	lib->searchList=(LinkMap **)malloc(depd_cnt);
	for (int i=0;i<depd_cnt;++i)
		lib->searchList[i]=tempList[i];

	return lib;
}

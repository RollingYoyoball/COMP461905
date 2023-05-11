#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>

#include "Link.h"

// glibc version to hash a symbol
	static uint_fast32_t
dl_new_hash(const char *s)
{
	uint_fast32_t h = 5381;
	for (unsigned char c = *s; c != '\0'; c = *++s)
		h = h * 33 + c;
	return h & 0xffffffff;
}

// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{
	if(dep->fake)
	{
		void *handle = dlopen(dep->name, RTLD_LAZY);
		if(!handle)
		{
			fprintf(stderr, "relocLibrary error: cannot dlopen a fake object named %s", dep->name);
			abort();
		}
		dep->fakeHandle = handle;
		return dlsym(handle, name);
	}

	Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
	const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

	uint_fast32_t new_hash = dl_new_hash(name);
	Elf64_Sym *sym;
	const Elf64_Addr *bitmask = dep->l_gnu_bitmask;
	uint32_t symidx;
	Elf64_Addr bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & dep->l_gnu_bitmask_idxbits];
	unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
	unsigned int hashbit2 = ((new_hash >> dep->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));
	if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
	{
		Elf32_Word bucket = dep->l_gnu_buckets[new_hash % dep->l_nbuckets];
		if (bucket != 0)
		{
			const Elf32_Word *hasharr = &dep->l_gnu_chain_zero[bucket];
			do
			{
				if (((*hasharr ^ new_hash) >> 1) == 0)
				{
					symidx = hasharr - dep->l_gnu_chain_zero;
					/* now, symtab[symidx] is the current symbol.
					   Hash table has done its job */
					const char *symname = strtab + symtab[symidx].st_name;
					if (!strcmp(symname, name))
					{    
						Elf64_Sym *s = &symtab[symidx];
						// return the real address of found symbol
						return (void *)(s->st_value + dep->addr);
					}
				}
			} while ((*hasharr++ & 1u) == 0);
		}
	}
	return NULL; //not this dependency
}

char *GetSymbolName(char *string_table){
	int sym_len=0;
	char temp_str[100];
	for (int i=0;string_table[i]!=0;++i){
		temp_str[sym_len++]=string_table[i];
	}
	char *symbol_name=(char *)malloc(sym_len+1);
	memcpy(symbol_name,temp_str,sizeof(char)*sym_len);
	symbol_name[sym_len]=0;
	return symbol_name;
}

const int QLEN=1000;
int GetOrder(LinkMap *ori_lib,LinkMap **lib_list){
	LinkMap *q[QLEN];
	LinkMap *lib;
	int list_len=0;
	int head=0,tail=0;

	int needed_cnt=0;

	q[tail++]=ori_lib;
	do{
		lib=q[head++];

		lib_list[list_len++]=lib;
		needed_cnt=0;
		for (Elf64_Dyn *dyn=lib->dyn;dyn->d_tag!=DT_NULL;dyn++){
			if (dyn->d_tag==DT_NEEDED)
				++needed_cnt;
		}
		LinkMap *temp_lib;
		for (int j=0;j<needed_cnt;++j){
			temp_lib=lib->searchList[j];
			if (temp_lib->fake)
				continue;
			q[tail++]=temp_lib;
		}
	}while (head!=tail);
	return list_len;
}

void Relocate(LinkMap *lib,int mode){/*{{{*/
	Elf64_Dyn *dyn;
	int dyn_size=sizeof(Elf64_Dyn);    
	int plt_rela_size=sizeof(Elf64_Rela);//function reloctations
	int dyn_rela_size;//relative relocations
	int total_dyn_size,total_plt_size;
	int rela_count;

	Elf64_Rela *plt_entry=NULL,*dyn_entry=NULL;
	char *string_table=NULL;
	void *symbol_table=NULL;
	int lib_name_offset[100];
	int have_needed=0;//have needed?
	int needed_cnt=0;

	for (dyn=lib->dyn;dyn->d_tag!=DT_NULL;dyn++){
		if (dyn->d_tag==DT_RELASZ){
			total_dyn_size=dyn->d_un.d_val;
		}
		else if (dyn->d_tag==DT_RELA){
			dyn_entry=(Elf64_Rela *)dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag==DT_SYMTAB){
			symbol_table=(void *)dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag==DT_STRTAB){
			string_table=(char *)dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag==DT_NEEDED){
			lib_name_offset[needed_cnt++]=(int)dyn->d_un.d_val;
			have_needed=1;
		}
		else if (dyn->d_tag==DT_PLTRELSZ){
			total_plt_size=(int)dyn->d_un.d_val;
		}
		else if (dyn->d_tag==DT_JMPREL){
			plt_entry=(Elf64_Rela *)dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag==DT_RELAENT){
			dyn_rela_size=(int)dyn->d_un.d_val;
		}
		else if (dyn->d_tag==DT_RELACOUNT){
			rela_count=dyn->d_un.d_val;
		}
	}

	int n=total_plt_size/plt_rela_size;
	uint64_t reloc_type,sym_index;
	void *address;
	char *symbol_name;
	int *str_offset_ptr,str_offset;
	uint64_t real_addr,*r_offset;

	if (have_needed){
		//debug only
		//printf("%s\n",lib_name);	


		//task2
		for (int i=0;i<n;++i){
			sym_index=plt_entry[i].r_info>>32;
			reloc_type=plt_entry[i].r_info-(sym_index<<32);

			//get symbol name
			str_offset_ptr=(int *)((char *)symbol_table+sym_index*sizeof(Elf64_Sym));
			str_offset=*str_offset_ptr;

			symbol_name=GetSymbolName(string_table+str_offset);

			LinkMap *temp_lib;
			address=NULL;
			for (int j=0;j<needed_cnt;++j){
				temp_lib=lib->searchList[j];
				address=symbolLookup(temp_lib,symbol_name);
				if (address!=NULL)
					break;
			}

			r_offset=(uint64_t *)(lib->addr+plt_entry[i].r_offset);
			real_addr=(uint64_t)address+plt_entry[i].r_addend;
			*r_offset=real_addr;
		}
	}

	//task3 relocation part
	n=total_dyn_size/dyn_rela_size;
	//relative entries
	for (int i=0;i<rela_count;++i){
		r_offset=(uint64_t *)(lib->addr+dyn_entry[i].r_offset);
		real_addr=(uint64_t)lib->addr+dyn_entry[i].r_addend;
		*r_offset=real_addr;
		//debug only
		//printf("addend = %lx   r_offset = %lx   real_addr = %lx\n",dyn_entry[i].r_addend,r_offset,*r_offset);
	}

	//global entries;
	for (int i=rela_count;i<n;++i){
		sym_index=dyn_entry[i].r_info>>32;
		reloc_type=dyn_entry[i].r_info-(sym_index<<32);

		//get symbol name
		str_offset_ptr=(int *)((char *)symbol_table+sym_index*sizeof(Elf64_Sym));
		str_offset=*str_offset_ptr;

		symbol_name=GetSymbolName(string_table+str_offset);

		LinkMap *temp_lib;
		address=symbolLookup(lib,symbol_name);
		if (address==NULL)//can't find
			continue;

		r_offset=(uint64_t *)(lib->addr+dyn_entry[i].r_offset);
		real_addr=(uint64_t)address+dyn_entry[i].r_addend;
		*r_offset=real_addr;
	}

}/*}}}*/

void RelocLibrary(LinkMap *lib, int mode)
{
	/* Your code here */
	LinkMap *list[QLEN];
	int list_len=GetOrder(lib,list);
	for (int i=list_len-1;~i;--i){
		Relocate(list[i],mode);
	}
}

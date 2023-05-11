#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>

#include "Link.h"
#include "LoaderInternal.h"

void InitLibrary(LinkMap *l)
{
	/* Your code here */

	Elf64_Dyn *dyn;
	int dyn_size=sizeof(Elf64_Dyn);    
	void (*init_function)(void)=NULL;//function address
	uint64_t *init_function_array;//an array storing the address of init functions
	int array_size;

	for (dyn=l->dyn;dyn->d_tag!=DT_NULL;dyn++){
		if (dyn->d_tag==DT_INIT){
			init_function=(void *)dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag==DT_INIT_ARRAY){
			init_function_array=(uint64_t *)dyn->d_un.d_ptr;
		}
		else if (dyn->d_tag==DT_INIT_ARRAYSZ){
			array_size=(int)dyn->d_un.d_val;
		}
	}
	int entry_size=sizeof(void *);
	int n=array_size/entry_size;

	//debug only 
	//printf("init function addr = %lx\n",init_function);

	for (int i=0;i<n;++i){
		init_function=(void *)init_function_array[i];
		//debug only
		//printf("init_function addr = %lx\n",init_function_array+offset);
		init_function();
	}
}

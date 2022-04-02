/*Documentation used:
 *Libelf by example - Joseph Koshy, January 2010
 *fossies.org/dox/libelf
 *man.openbsd.org
 *docs.oracle.com
 */

/*Compilation
 *gcc main.c -lcapstone -lelf -o pdump
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <elf.h>
#include <capstone/capstone.h>

#define SEC_NAME_MAX 30

typedef struct
{
	int bits;
	int arch;
	u_long vma;
}
cs_config;

void cleanup(Elf *e_fd, int fd, GElf_Ehdr *e_hdr)
{
	close(fd);
	elf_end(e_fd);
	free(e_hdr);
}

/*prints the human-readable format of a cs_insn array */
void print_instructions(cs_insn *ins, size_t ins_n)
{
	for (size_t i = 0; i < ins_n; i++)
	{
		printf("Ox%08lx: ", ins[i].address);
		for (size_t j = 0; j < 16; j++)
		{
			if (j < ins[i].size) printf("%02x ", ins[i].bytes[j]);
			else printf("  ");
		}
		printf("%*s%s %s\n", 12 - ins[i].size, " ", ins[i].mnemonic, ins[i].op_str);
	}
}

/*linearly disassembles a buffer of interpretable bytes
 *returns -1 on failure, 1 on success
 */

int linear_disasm(char *sec_contents, size_t sec_size, csh dis_hd, cs_config *config)
{
	cs_insn * instructions;
	size_t ins_n;
	ins_n = cs_disasm(dis_hd, sec_contents, sec_size, config->vma, 0, &instructions);
	if (ins_n <= 0)
	{
		fprintf(stderr, "Failed to disassemble chunk of code (%ld)\n", ins_n);
		return -1;
	}
	print_instructions(instructions, ins_n);
	cs_free(instructions, ins_n);
	return 1;

}

/*this function retrieves the architecture and mode for configuring  */
void get_cs_config(Elf *e_fd, GElf_Ehdr *e_hdr, cs_config *sys_info)
{
	switch (gelf_getclass(e_fd))
	{
		case ELFCLASS32:
			sys_info->bits = CS_MODE_32;
			break;
		case ELFCLASS64:
			sys_info->bits = CS_MODE_64;
			break;
		default:
			break;
	}
	switch (e_hdr->e_machine)
	{
		case EM_X86_64:
			sys_info->arch = CS_ARCH_X86;
			break;
		case EM_386:
			sys_info->arch = CS_ARCH_X86;
			break;
		case EM_ARM:
			if (sys_info->bits == 64)
			{
				sys_info->arch = CS_ARCH_ARM64;
			}
			else
			{
				sys_info->arch = CS_ARCH_ARM;
			}
			sys_info->bits = CS_MODE_ARM;
			break;
		default:
			fprintf(stderr, "Unable to identify architecture/mode, using default x86_64\n");
			sys_info->arch = CS_ARCH_X86;
			sys_info->bits = CS_MODE_64;
			break;
	}
}

/*disassembles and prints the contents of section referred to by name
 *returns -1 on failure
 *returns 1 on success
 */
int disass_section(Elf *e_fd, GElf_Ehdr *e_hdr, char *name)
{
	Elf_Scn *scn = (Elf_Scn*) NULL;
	size_t shstrndx;
	char *s_name;
	GElf_Shdr dst_shdr;
	Elf_Data * sec_data;
	/*retrieve the index of .shstrtab */
	if (elf_getshdrstrndx(e_fd, &shstrndx))
	{
		perror("Failed to get shstrndx: ");
		return -1;
	}
	/*loop through the section headers and contents */
	while ((scn = elf_nextscn(e_fd, scn)))
	{
		if (!gelf_getshdr(scn, &dst_shdr))
		{
			perror("Failed to get section header: ");
			return -1;
		}
		s_name = elf_strptr(e_fd, shstrndx, dst_shdr.sh_name);
		if (!s_name)
		{
			fprintf(stderr, "Failed to retrieve section name\n");
			return -1;
		}
		/*checking if current section is the section specified by char *name */
		if (strncmp(s_name, name, SEC_NAME_MAX) == 0)
		{

			/*getting cs_config information */
			cs_config *config = (cs_config*) malloc(sizeof(cs_config));
			get_cs_config(e_fd, e_hdr, config);
			config->vma = dst_shdr.sh_offset;
			size_t dsize = 0;
			/*configuring capstone */
			csh dis_hd;
			if (cs_open(config->arch, config->bits, &dis_hd) != CS_ERR_OK)
			{
				free(config);
				fprintf(stderr, "Failed to configure capstone\n");
				return -1;
			}
			/*looping through the chunks of raw section data */
			while (((sec_data = elf_rawdata(scn, NULL)) != NULL && sec_data->d_buf != NULL && dsize < dst_shdr.sh_size))
			{ /*disassemble the current chunk of data */
				linear_disasm(sec_data->d_buf, sec_data->d_size, dis_hd, config);
				dsize += sec_data->d_size;
			}
			if (dsize < dst_shdr.sh_size)
			{
				fprintf(stderr, "[WARNING] Unable to disassemble entire section\n");
			}
			cs_close(&dis_hd);
			free(config);
			return 1;
		}
	}
	fprintf(stderr, "Failed to find section header: %s\n", name);
	return -1;
}

int main(int argc, char *argv[])
{
	char *bin_name;
	char sec_name[SEC_NAME_MAX];
	int bin_fd;
	Elf * e_fd;
	/*parsing command line arguments */
	if (argc < 2)
	{
		printf("Usage: %s < binary>[section] \n", argv[0]);
		return 1;
	}
	else if (argc >= 3)
	{
		strncpy(sec_name, argv[2], SEC_NAME_MAX);
	}
	else if (argc == 2)
	{
		printf("No section name provided, disassembling .text\n");
		strncpy(sec_name, ".text", SEC_NAME_MAX);
	}
	/*preparing the binary to be parsed */
	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		fprintf(stderr, "Unsupported libelf version\n");
		return 1;
	}

	bin_name = argv[1];
	bin_fd = open(bin_name, O_RDONLY);
	if (bin_fd < 0)
	{
		fprintf(stderr, "fopen() could not open file: %s\n", argv[1]);
		return 1;
	}

	e_fd = elf_begin(bin_fd, ELF_C_READ, (Elf*) 0);
	if (!e_fd)
	{
		fprintf(stderr, "elf_begin() could not ELF file: %s\n", argv[1]);
		close(bin_fd);
	}

	GElf_Ehdr *e_hdr = (GElf_Ehdr*) malloc(sizeof(GElf_Ehdr));

	if (elf_kind(e_fd) == ELF_K_NONE)
	{
		fprintf(stderr, "Could not identify file, %s, as ELF archive or file\n", argv[1]);
		cleanup(e_fd, bin_fd, e_hdr);
		return 1;
	}

	if (!gelf_getehdr(e_fd, e_hdr))
	{
		cleanup(e_fd, bin_fd, e_hdr);
		fprintf(stderr, "failed to retrieve executable header\n");
		return 1;
	}
	/*disassemble section specified by sec_name */
	printf("Disassembly of section %s\n", sec_name);
	if (disass_section(e_fd, e_hdr, sec_name) < 0)
	{
		cleanup(e_fd, bin_fd, e_hdr);
		return 1;
	}

	cleanup(e_fd, bin_fd, e_hdr);
	return 0;
}

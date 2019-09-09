#include "RestoreMacroCompression.h"
#define USE_DANGEROUS_FUNCTIONS
#include <hexrays.hpp>
#include <plthook.h>

#define FCHUNK_MAXSIZE 0x60
#define FCHUNK_MINSN_MAXSIZE 0x30

enum asm_type
{
	at_unknown,
	at_x86,
	at_x64,
	at_arm,
	at_arm64
};

struct mba_info
{
	time_t time;
	bool modified;
	int retn;
	mbl_array_t* mba;
	intptr_t hash;
};

asm_type cur_asm_type;
plthook_t* plthook;
std::map<ea_t, mba_info> microcode_cache;
std::map<qstring, mop_t> mop_cache;
bool is_preload = false;

intptr_t right_shift_loop(intptr_t num, intptr_t n)
{
	return (num << (sizeof(intptr_t) - n) | (num >> n));
}

bool is_sub(ea_t ea)
{
	qstring name;
	get_name(&name, ea);
	char* p_name = (char*)name.c_str();
	if (memcmp(p_name, "sub_", 4) == 0 || memcmp(p_name, "loc_", 4) == 0)
	{
		ea_t n = strtoull(p_name + 4, NULL, 16);
		return ea == n;
	}
	return false;
}

bool is_minsn_goto_ea(minsn_t* minsn)
{
	return minsn->opcode == m_goto && minsn->l.t == mop_v;
}

bool is_minsn_call_ea(minsn_t* minsn)
{
	return minsn->opcode == m_call && minsn->l.t == mop_v;
}

intptr_t get_minsn_hash(minsn_t* minsn);

intptr_t get_mop_hash(mop_t* mop)
{
	intptr_t hash = mop->t;
	hash = mop->oprops ^ right_shift_loop(hash, sizeof(mop->t));
	hash = mop->valnum ^ right_shift_loop(hash, sizeof(mop->oprops));
	hash = mop->size ^ right_shift_loop(hash, sizeof(mop->valnum));
	hash = right_shift_loop(hash, sizeof(mop->size));
	switch (mop->t)
	{
	case mop_r:
		hash ^= mop->r;
		break;
	case mop_n:
		hash ^= mop->nnn->value;
		break;
	case mop_str:
		hash ^= *(mop->cstr);
		break;
	case mop_d:
		hash ^= get_minsn_hash(mop->d);
		break;
	case mop_S:
		//hash ^= mop->s;
		break;
	case mop_v:
		hash ^= mop->g;
		break;
	case mop_b:
		hash ^= mop->b;
		break;
	case mop_f:
		//hash ^= mop->f;
		break;
	case mop_l:
		//hash ^= mop->l;
		break;
	case mop_a:
		hash ^= get_mop_hash(mop->a);
		break;
	case mop_h:
		hash ^= *(mop->helper);
		break;
	case mop_c:
		//hash ^= mop->c;
		break;
	case mop_fn:
		//hash ^= mop->fpc;
		break;
	case mop_p:
		hash ^= get_mop_hash(&(mop->pair->hop)) ^ get_mop_hash(&(mop->pair->lop));
		break;
	case mop_sc:
		//hash ^= mop->scif;
		break;
	default:
		break;
	}
	return hash;
}

intptr_t get_minsn_hash(minsn_t* minsn)
{
	intptr_t l = get_mop_hash(&(minsn->l));
	intptr_t r = get_mop_hash(&(minsn->r));
	intptr_t d = get_mop_hash(&(minsn->d));
	intptr_t c = right_shift_loop(l, 16) ^ right_shift_loop(r, 8) ^ d;
	int n = (sizeof(intptr_t) * 8) - 8;
	intptr_t t = minsn->opcode << n;
	intptr_t hash = t ^ c;
	return hash;
}

intptr_t get_mba_hash(mbl_array_t* mba)
{
	const uint32_t table[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
	};
	intptr_t hash = 0;
	for (int i = 0; i < mba->qty; i++)
	{
		mblock_t* block = mba->get_mblock(i);
		minsn_t* insn = block->head;
		while (insn != NULL)
		{
			hash = table[(hash ^ get_minsn_hash(insn)) & 0xff] ^ right_shift_loop(hash, 8);
			insn = insn->next;
		}
	}
	hash ^= -1;
	return hash;
}

mblock_t* get_blk(mblock_t* blk, ea_t ea)
{
	for (mblock_t* block = blk; block != NULL; block = block->nextb)
	{
		if (block->start <= ea && block->end > ea)
			return block;
	}
	return NULL;
}

mblock_t* get_blk(mbl_array_t* mba, ea_t ea)
{
	return get_blk(mba->blocks, ea);
}

int get_mba_retn(mbl_array_t* mba)
{
	int retn = 0;
	for (int i = 0; i < mba->qty; i++)
	{
		mblock_t* block = mba->get_mblock(i);
		minsn_t* insn = block->tail;
		if (insn != NULL)
		{
			if (insn->opcode == m_ret)
				retn++;
			else if (is_minsn_goto_ea(insn))
			{
				ea_t address = insn->l.g;
				if (get_blk(mba, address) == NULL)
					retn++;
			}
		}
	}
	return retn;
}

int get_minsn_count(mbl_array_t* mba)
{
	int count = 0;
	for (int i = 0; i < mba->qty; i++)
	{
		mblock_t* block = mba->get_mblock(i);
		for (minsn_t* insn = block->head; insn != NULL; insn = insn->next)
		{
			if (insn->opcode != m_nop)
				count++;
		}
	}
	return count;
}

void blk_cpy(mblock_t* dst, mblock_t* src, ea_t ea = BADADDR)
{
	dst->flags = src->flags;
	dst->start = src->start;
	dst->end = src->end;
	dst->type = src->type;
	//dst->dead_at_start = src->dead_at_start;
	//dst->mustbuse = src->mustbuse;
	//dst->maybuse = src->maybuse;
	//dst->mustbdef = src->mustbdef;
	//dst->maybdef = src->maybdef;
	//dst->dnu = src->dnu;
	//dst->maxbsp = src->maxbsp;
	//dst->minbstkref = src->minbstkref;
	//dst->minbargref = src->minbargref;
	//dst->predset = src->predset;
	//dst->succset = src->succset;
	minsn_t* src_insn = src->head;
	minsn_t* dst_insn = NULL;
	while (src_insn != NULL)
	{
		minsn_t* new_insn = new minsn_t(*src_insn);
		new_insn->ea = ea == BADADDR ? src_insn->ea : ea;
		dst_insn = dst->insert_into_block(new_insn, dst_insn);
		src_insn = src_insn->next;
	}
}

bool mba_cmp(mbl_array_t* mba1, mbl_array_t* mba2)
{
	return mba1 == mba2 || get_mba_hash(mba1) == get_mba_hash(mba2);
}

void mba_cpy(mbl_array_t* dst, mbl_array_t* src, ea_t ea = BADADDR)
{
	for (int i = dst->qty - 1; i >= 0; i--)
	{
		mblock_t* dst_block = dst->get_mblock(i);
		dst->remove_block(dst_block);
	}
	for (int i = 0; i < src->qty; i++)
	{
		mblock_t* dst_block = dst->insert_block(i);
		dst_block->flags |= MBL_FAKE;
	}
	for (int i = 0; i < src->qty; i++)
	{
		mblock_t* src_block = src->get_mblock(i);
		mblock_t* dst_block = dst->get_mblock(i);
		blk_cpy(dst_block, src_block, ea);
	}
}

mop_t get_mop(const char* reg_name, int s)
{
	char reg_full_name[24];
	sprintf_s(reg_full_name, "%s.%d", reg_name, s);
	auto it = mop_cache.find(reg_full_name);
	if (it != mop_cache.end())
		return it->second;
	mop_t mop(0, s);
	try
	{
		while (true)
		{
			if (strcmp(mop.dstr(), reg_full_name) == 0)
				break;
			mop.r++;
		}
	}
	catch (const std::exception&)
	{
		mop.zero();
	}
	mop_cache[reg_full_name] = mop;
	return mop;
}

qvector<mblock_t*> get_all_blk(mblock_t* blk)
{
	qvector<mblock_t*> blk_list;
	for (mblock_t* cur_blk = blk; cur_blk != NULL && cur_blk->type != BLT_STOP; cur_blk = cur_blk->nextb)
	{
		if (cur_blk->tail != NULL || blk_list.size())
			blk_list.push_back(cur_blk);
	}
	return blk_list;
}

mblock_t* get_last_blk(mblock_t* begin_blk, mblock_t* end_blk)
{
	for (mblock_t* cur_blk = end_blk; cur_blk != NULL && cur_blk != begin_blk; cur_blk = cur_blk->prevb)
	{
		if (cur_blk->tail != NULL)
			return cur_blk;
	}
}

mba_info* PreloadMacroCompression(const mba_ranges_t& mbr);

void FixSP(mblock_t* block, ea_t ea, bool sub = false, minsn_t* position = NULL)
{
	minsn_t* insn = new minsn_t(ea);
	insn->opcode = sub ? m_sub : m_add;
	switch (cur_asm_type)
	{
	case at_unknown:
		insn->_make_nop();
		return;
	case at_x86:
		insn->l = insn->d = get_mop("esp", 4);
		insn->r.make_number(4, 4, ea);
		break;
	case at_x64:
		insn->l = insn->d = get_mop("rsp", 8);
		insn->r.make_number(8, 8, ea);
		break;
	case at_arm:
		insn->l = insn->d = get_mop("sp", 4);
		insn->r.make_number(4, 4, ea);
		break;
	case at_arm64:
		insn->l = insn->d = get_mop("sp", 8);
		insn->r.make_number(8, 8, ea);
		break;
	default:
		break;
	}
	block->insert_into_block(insn, position);
}

void FixBlockSerial(mblock_t* begin_block, mblock_t* end_block, std::map<int, int>& serial_map)
{
	for (mblock_t* block = begin_block; block != NULL && block != end_block; block = block->nextb)
	{
		for (minsn_t* insn = block->head; insn != NULL; insn = insn->next)
		{
			if (insn->l.t == mop_b)
				insn->l.b = serial_map[insn->l.b];
			if (insn->r.t == mop_b)
				insn->r.b = serial_map[insn->r.b];
			if (insn->d.t == mop_b)
				insn->d.b = serial_map[insn->d.b];
		}
	}
}

void FixBlockSerial(mblock_t* blocks, int serial, int offset)
{
	for (mblock_t* block = blocks; block != NULL; block = block->nextb)
	{
		for (minsn_t* insn = block->head; insn != NULL; insn = insn->next)
		{
			if (insn->l.t == mop_b && insn->l.b >= serial)
				insn->l.b += offset;
			if (insn->r.t == mop_b && insn->r.b >= serial)
				insn->r.b += offset;
			if (insn->d.t == mop_b && insn->d.b >= serial)
				insn->d.b += offset;
		}
	}
}

void RestoreMacroCompression(mbl_array_t* mba, mblock_t* fchunk_mba, int& index)
{
	mblock_t* block = mba->get_mblock(index);
	minsn_t* insn = block->tail;
	ea_t cur_ea = insn->ea;
	bool fix_sp = insn->opcode != m_goto;
	insn->_make_nop();
	mblock_t* first_block = NULL;
	mblock_t* last_block = NULL;
	mblock_t* cur_block = NULL;
	qvector<mblock_t*> block_list = get_all_blk(fchunk_mba);
	FixBlockSerial(mba->blocks, block->nextb->serial, block_list.size());
	std::map<int, int> serial_map;
	for (mblock_t* fchunk_block : block_list)
	{
		mblock_t* new_block = mba->insert_block(++index);
		serial_map[fchunk_block->serial] = new_block->serial;
		blk_cpy(new_block, fchunk_block, cur_ea);
		new_block->start = cur_ea;
		new_block->end = block->end;
		if (first_block == NULL)
			first_block = new_block;
		last_block = new_block;
		if (new_block->tail != NULL)
		{
			cur_block = new_block;
			minsn_t* last_insn = new_block->tail;
			if (last_insn->opcode == m_goto && last_insn->l.t == mop_v)
			{
				ea_t address = last_insn->l.g;
				mblock_t* tmp_block = get_blk(fchunk_mba, address);
				if (tmp_block != NULL)
				{
					last_insn->l.t = mop_b;
					last_insn->l.b = tmp_block->serial;
				}
			}
		}
	}
	if (cur_block != NULL)
	{
		FixBlockSerial(first_block, cur_block->nextb, serial_map);
		minsn_t* last_insn = cur_block->tail;
		if (last_insn->opcode == m_ret)
			last_insn->_make_nop();
		else if (is_minsn_goto_ea(last_insn))
		{
			last_insn->opcode = m_call;
		}
		if (fix_sp)
		{
			FixSP(first_block, first_block->start, true);
			FixSP(last_block, cur_block->tail->ea, false, last_block->tail);
		}
	}
	//if (first_block != NULL)
	//{
	//	insn->opcode = m_goto;
	//	ea_t address = last_block->tail == NULL ? last_block->start : last_block->tail->ea;
	//	minsn_t* ret_insn = new minsn_t(address);
	//	ret_insn->opcode = m_goto;
	//	ret_insn->l.t = mop_v;
	//	ret_insn->l.g = last_block->nextb->start;
	//	last_block->insert_into_block(ret_insn, last_block->tail);
	//}
}

mba_info* PreloadMacroCompression(const mba_ranges_t& mbr)
{
	time_t t = time(NULL);
	auto it = microcode_cache.find(mbr.start());
	if (it != microcode_cache.end())
	{
		time_t x = t - it->second.time;
		if ((it->second.mba != NULL && x < 120))
			return &it->second;
	}
	mba_info& info = microcode_cache[mbr.start()];
	info.time = t;
	mbl_array_t* mba = gen_microcode(mbr, NULL, NULL, DECOMP_NO_WAIT, MMAT_GENERATED);
	if (mba != NULL && info.mba != mba)
	{
		intptr_t mba_hash = get_mba_hash(mba);
		if (info.hash != mba_hash)
		{
			info.retn = get_mba_retn(mba);
			info.mba = mba;
			info.hash = mba_hash;
			for (int i = 0; i < mba->qty; i++)
			{
				mblock_t* block = mba->get_mblock(i);
				minsn_t* insn = block->tail;
				if (insn != NULL && is_minsn_call_ea(insn))
				{
					ea_t address = insn->l.g;
					if (is_sub(address))
					{
						func_t* pfn = get_func(address);
						if (pfn != NULL && pfn->start_ea == address && pfn->size() <= FCHUNK_MAXSIZE)
						{
							mba_info* fchunk_mba = PreloadMacroCompression(pfn);
							if (fchunk_mba != NULL && fchunk_mba->mba != NULL && fchunk_mba->retn <= 1 && get_minsn_count(fchunk_mba->mba) <= FCHUNK_MINSN_MAXSIZE)
								RestoreMacroCompression(mba, fchunk_mba->mba->blocks, i);
						}
					}
				}
			}
			mblock_t* last_block = get_last_blk(mba->get_mblock(0), mba->get_mblock(mba->qty - 1));
			if (last_block != NULL)
			{
				minsn_t* last_insn = last_block->tail;
				if (is_minsn_goto_ea(last_insn))
				{
					ea_t address = last_insn->l.g;
					if (is_sub(address) && get_blk(mba, address) == NULL)
					{
						func_t* pfn = get_func(address);
						if (pfn != NULL)
						{
							if (pfn->start_ea == address)
							{
								if (pfn->size() <= FCHUNK_MAXSIZE)
								{
									mba_info* fchunk_mba = PreloadMacroCompression(pfn);
									if (fchunk_mba != NULL && fchunk_mba->mba != NULL && fchunk_mba->retn <= 1 && get_minsn_count(fchunk_mba->mba) <= FCHUNK_MINSN_MAXSIZE)
									{
										int index = last_block->serial;
										RestoreMacroCompression(mba, fchunk_mba->mba->blocks, index);
									}
								}
							}
							else
							{
								mba_info* fchunk_mba = PreloadMacroCompression(pfn);
								if (fchunk_mba != NULL && fchunk_mba->mba != NULL)
								{
									mblock_t* fchunk_block = get_blk(fchunk_mba->mba, address);
									if (fchunk_block != NULL)
									{
										int index = last_block->serial;
										RestoreMacroCompression(mba, fchunk_block, index);
									}
								}
							}
						}
					}
				}
			}
			info.modified = mba_hash != get_mba_hash(mba);
		}
	}
	return &info;
}

ssize_t idaapi hexrays_callback(void* ud, hexrays_event_t event, va_list va)
{
	if (is_preload == false && event == hxe_microcode)
	{
		mbl_array_t* mba = va_arg(va, mbl_array_t*);
		auto it = microcode_cache.find(mba->entry_ea);
		if (it != microcode_cache.end())
		{
			if (it->second.modified && it->second.mba != NULL && it->second.mba != mba && it->second.hash == get_mba_hash(mba))
				mba_cpy(mba, it->second.mba);
		}
	}
	return 0;
}

ssize_t idaapi ui_notification(void* user_data, int notification_code, va_list va)
{
	if (notification_code == ui_preprocess_action)
	{
		char* name = va_arg(va, char*);
		msg("ui_preprocess_action: %s\n", name);
		if (strcmp(name, "hx:GenPseudo") == 0)
		{
			func_t* pfn = get_func(get_screen_ea());
			if (pfn != NULL)
			{
				is_preload = true;
				PreloadMacroCompression(pfn);
				is_preload = false;
			}
		}
	}
	return 0;
}

decltype(get_func)* old_get_func;

idaman func_t* ida_export new_get_func(ea_t ea)
{
	func_t* pfn = get_func(ea);
	if (is_preload == false && pfn != NULL)
	{
		is_preload = true;
		PreloadMacroCompression(pfn);
		is_preload = false;
	}
	return pfn;
}

void InitRestoreMacroCompression()
{
	if (strcmp(inf.procname, "ARM") == 0 || strcmp(inf.procname, "ARMB") == 0) //arm
		cur_asm_type = inf_is_64bit() ? at_arm64 : at_arm;
	else if (memcmp(inf.procname, "80386", 5) == 0 || memcmp(inf.procname, "80486", 5) == 0 || memcmp(inf.procname, "80586", 5) == 0 || memcmp(inf.procname, "80686", 5) == 0 || strcmp(inf.procname, "metapc") == 0 || strcmp(inf.procname, "p2") == 0 || strcmp(inf.procname, "p3") == 0 || strcmp(inf.procname, "p4") == 0)
		cur_asm_type = inf_is_64bit() ? at_x64 : at_x86;
	else
		cur_asm_type = at_unknown;
	install_hexrays_callback(&hexrays_callback, NULL);
	//hook_to_notification_point(HT_UI, &ui_notification, NULL);
	if (plthook_open_by_address(&plthook, hexdsp) == PLTHOOK_SUCCESS)
		plthook_replace(plthook, "get_func", &new_get_func, (void**)& old_get_func);
}

void UnInitRestoreMacroCompression()
{
	remove_hexrays_callback(&hexrays_callback, NULL);
	//unhook_from_notification_point(HT_UI, &ui_notification, NULL);
	plthook_replace(plthook, "get_func", old_get_func, NULL);
	plthook_close(plthook);
	microcode_cache.clear();
	mop_cache.clear();
}

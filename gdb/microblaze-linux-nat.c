/* Native-dependent code for GNU/Linux MicroBlaze.
   Copyright (C) 2021 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "arch-utils.h"
#include "dis-asm.h"
#include "frame.h"
#include "trad-frame.h"
#include "symtab.h"
#include "value.h"
#include "gdbcmd.h"
#include "breakpoint.h"
#include "inferior.h"
#include "gdbthread.h"
#include "gdbcore.h"
#include "regcache.h"
#include "regset.h"
#include "target.h"
#include "frame.h"
#include "frame-base.h"
#include "frame-unwind.h"
#include "osabi.h"
#include "gdbsupport/gdb_assert.h"
#include <string.h>
#include "target-descriptions.h"
#include "opcodes/microblaze-opcm.h"
#include "opcodes/microblaze-dis.h"
#include "gregset.h"

#include "linux-nat.h"
#include "linux-tdep.h"
#include "target-descriptions.h"

#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include "gdbsupport/gdb_wait.h"
#include <fcntl.h>
#include <sys/procfs.h>
#include "nat/gdb_ptrace.h"
#include "nat/linux-ptrace.h"
#include "inf-ptrace.h"
#include <algorithm>
#include <unordered_map>
#include <list>
#include <sys/ptrace.h>

/* Prototypes for supply_gregset etc. */
#include "gregset.h"

#include "microblaze-tdep.h"
#include "microblaze-linux-tdep.h"
#include "inferior.h"

#include "elf/common.h"

#include "auxv.h"
#include "linux-tdep.h"

#include <sys/ptrace.h>


//int have_ptrace_getsetregs=1;

/* MicroBlaze Linux native additions to the default linux support.  */

class microblaze_linux_nat_target final : public linux_nat_target
{
public:
  /* Add our register access methods.  */
  void fetch_registers (struct regcache *regcache, int regnum) override;
  void store_registers (struct regcache *regcache, int regnum) override;

  /* Read suitable target description.  */
  const struct target_desc *read_description () override;
};

static microblaze_linux_nat_target the_microblaze_linux_nat_target;

static int
microblaze_register_u_addr (struct gdbarch *gdbarch, int regno)
{
  int u_addr = -1;
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  /* NOTE: cagney/2003-11-25: This is the word size used by the ptrace
 *      interface, and not the wordsize of the program's ABI.  */
  int wordsize = sizeof (long);

  /* General purpose registers occupy 1 slot each in the buffer.  */
  if (regno >= MICROBLAZE_R0_REGNUM
      && regno <= MICROBLAZE_FSR_REGNUM)
    u_addr = ((regno - MICROBLAZE_R0_REGNUM)* wordsize);

  return u_addr;
}

/* Copy general purpose register REGNUM (or all gp regs if REGNUM == -1)
   from regset GREGS into REGCACHE.  */

static void
supply_gregset_regnum (struct regcache *regcache, const prgregset_t *gregs,
		       int regnum)
{
  int i;
  const elf_greg_t *regp = *gregs;
  /* Access all registers */
  if (regnum == -1)
    {
      /* We fill the general purpose registers.  */
      for (i = MICROBLAZE_R0_REGNUM + 1; i < MICROBLAZE_FSR_REGNUM; i++)
	regcache->raw_supply (i, regp + i);

      /* Supply MICROBLAZE_PC_REGNUM from index 32.  */
      regcache->raw_supply (MICROBLAZE_PC_REGNUM, regp + 32);

      /* Fill the inaccessible zero register with zero.  */
      regcache->raw_supply_zeroed (0);
    }
  else if (regnum == MICROBLAZE_R0_REGNUM)
    regcache->raw_supply_zeroed (0);
  else if (regnum == MICROBLAZE_PC_REGNUM)
    regcache->raw_supply (MICROBLAZE_PC_REGNUM, regp + 32);
  else if (regnum > MICROBLAZE_R0_REGNUM && regnum < MICROBLAZE_FSR_REGNUM)
    regcache->raw_supply (regnum, regp + regnum);
}

/* Copy all general purpose registers from regset GREGS into REGCACHE.  */

void
supply_gregset (struct regcache *regcache, const prgregset_t *gregs)
{
  supply_gregset_regnum (regcache, gregs, -1);
}

/* Copy general purpose register REGNUM (or all gp regs if REGNUM == -1)
   from REGCACHE into regset GREGS.  */

void
fill_gregset (const struct regcache *regcache, prgregset_t *gregs, int regnum)
{
  elf_greg_t *regp = *gregs;
  if (regnum == -1)
    {
      /* We fill the general purpose registers.  */
      for (int i = MICROBLAZE_R0_REGNUM + 1; i < MICROBLAZE_FSR_REGNUM; i++)
	regcache->raw_collect (i, regp + i);

      regcache->raw_collect (MICROBLAZE_PC_REGNUM, regp + 32);
    }
  else if (regnum == MICROBLAZE_R0_REGNUM)
    /* Nothing to do here.  */
    ;
  else if (regnum > MICROBLAZE_R0_REGNUM && regnum < MICROBLAZE_FSR_REGNUM)
    regcache->raw_collect (regnum, regp + regnum);
  else if (regnum == MICROBLAZE_PC_REGNUM)
    regcache->raw_collect (MICROBLAZE_PC_REGNUM, regp + 32);
}

/* Transfering floating-point registers between GDB, inferiors and cores.
   Since MicroBlaze floating-point registers are the same as GPRs these do
   nothing.  */

void
supply_fpregset (struct regcache *regcache, const gdb_fpregset_t *fpregs)
{
}

void
fill_fpregset (const struct regcache *regcache,
	       gdb_fpregset_t *fpregs, int regno)
{
}


static void
fetch_register (struct regcache *regcache, int tid, int regno)
{
  struct gdbarch *gdbarch = regcache->arch ();
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  /* This isn't really an address.  But ptrace thinks of it as one.  */
  CORE_ADDR regaddr = microblaze_register_u_addr (gdbarch, regno);
  int bytes_transferred;
  char buf[MICROBLAZE_MAX_REGISTER_SIZE];

  if (regaddr == -1)
  {
    memset (buf, '\0', register_size (gdbarch, regno));   /* Supply zeroes */
    regcache->raw_supply (regno, buf);
    return;
  }

  /* Read the raw register using sizeof(long) sized chunks.  On a
 *      32-bit platform, 64-bit floating-point registers will require two
 *           transfers.  */
  for (bytes_transferred = 0;
       bytes_transferred < register_size (gdbarch, regno);
       bytes_transferred += sizeof (long))
  {
    long l;

    errno = 0;
    l = ptrace (PTRACE_PEEKUSER, tid, (PTRACE_TYPE_ARG3) regaddr, 0);
    if (errno == EIO)
    {
      printf("ptrace io error\n");
    }
    regaddr += sizeof (long);
    if (errno != 0)
    {
      char message[128];
      sprintf (message, "reading register %s (#%d)",
               gdbarch_register_name (gdbarch, regno), regno);
      perror_with_name (message);
    }
    memcpy (&buf[bytes_transferred], &l, sizeof (l));
  }

  /* Now supply the register.  Keep in mind that the regcache's idea
 *      of the register's size may not be a multiple of sizeof
 *           (long).  */
  if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_LITTLE)
  {
    /* Little-endian values are always found at the left end of the
 *        bytes transferred.  */
    regcache->raw_supply (regno, buf);
  }
  else if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_BIG)
  {
    /* Big-endian values are found at the right end of the bytes
 *        transferred.  */
    size_t padding = (bytes_transferred - register_size (gdbarch, regno));
    regcache->raw_supply (regno, buf + padding);
  }
  else
    internal_error (__FILE__, __LINE__,
                    _("fetch_register: unexpected byte order: %d"),
                    gdbarch_byte_order (gdbarch));
}


/* This is a wrapper for the fetch_all_gp_regs function.  It is
 * responsible for verifying if this target has the ptrace request
 * that can be used to fetch all general-purpose registers at one
 * shot.  If it doesn't, then we should fetch them using the
 * old-fashioned way, which is to iterate over the registers and
 * request them one by one.  */
static void
fetch_gp_regs (struct regcache *regcache, int tid)
{
  int i;
/* If we've hit this point, it doesn't really matter which
   architecture we are using.  We just need to read the
   registers in the "old-fashioned way".  */
  for (i = MICROBLAZE_R0_REGNUM; i <= MICROBLAZE_FSR_REGNUM; i++)
    fetch_register (regcache, tid, i);
}

/* Return a target description for the current target.  */

const struct target_desc *
microblaze_linux_nat_target::read_description ()
{
  return tdesc_microblaze_linux;
}

/* Fetch REGNUM (or all registers if REGNUM == -1) from the target
   into REGCACHE using PTRACE_GETREGSET.  */

void
microblaze_linux_nat_target::fetch_registers (struct regcache * regcache,
                                              int regno)
{
  /* Get the thread id for the ptrace call.  */
  int tid = regcache->ptid ().lwp ();
//int tid = get_ptrace_pid (regcache->ptid());
#if 1 
  if (regno == -1)
#endif
    fetch_gp_regs (regcache, tid);
#if 1
  else
    fetch_register (regcache, tid, regno);
#endif
}


/* Store REGNUM (or all registers if REGNUM == -1) to the target
   from REGCACHE using PTRACE_SETREGSET.  */

void
microblaze_linux_nat_target::store_registers (struct regcache *regcache, int regno)
{
  int tid;

  tid = get_ptrace_pid (regcache->ptid ());

 struct gdbarch *gdbarch = regcache->arch ();
  /* This isn't really an address.  But ptrace thinks of it as one.  */
  CORE_ADDR regaddr = microblaze_register_u_addr (gdbarch, regno);
  int i;
  size_t bytes_to_transfer;
  char buf[MICROBLAZE_MAX_REGISTER_SIZE];

  if (regaddr == -1)
    return;

  /* First collect the register.  Keep in mind that the regcache's
 *      idea of the register's size may not be a multiple of sizeof
 *           (long).  */
  memset (buf, 0, sizeof buf);
  bytes_to_transfer = align_up (register_size (gdbarch, regno), sizeof (long));
  if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_LITTLE)
  {
    /* Little-endian values always sit at the left end of the buffer.  */
    regcache->raw_collect (regno, buf);
  }
  else if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_BIG)
  {
    /* Big-endian values sit at the right end of the buffer.  */
    size_t padding = (bytes_to_transfer - register_size (gdbarch, regno));
    regcache->raw_collect (regno, buf + padding);
  }

 for (i = 0; i < bytes_to_transfer; i += sizeof (long))
  { 
    long l;

    memcpy (&l, &buf[i], sizeof (l));
    errno = 0;
    ptrace (PTRACE_POKEUSER, tid, (PTRACE_TYPE_ARG3) regaddr, l);
    regaddr += sizeof (long);

    if (errno != 0)
    { 
      char message[128];
      sprintf (message, "writing register %s (#%d)",
               gdbarch_register_name (gdbarch, regno), regno);
      perror_with_name (message);
    }
  }
}

void _initialize_microblaze_linux_nat (void);

void
_initialize_microblaze_linux_nat (void)
{
  /* Register the target.  */
  linux_target = &the_microblaze_linux_nat_target;
  add_inf_child_target (linux_target);
}

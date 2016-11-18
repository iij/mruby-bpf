#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>

#include <err.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mruby.h"
#include "mruby/string.h"
#include "error.h"

static int
socket_fd(mrb_state *mrb, mrb_value sock)
{
    return mrb_fixnum(mrb_funcall(mrb, sock, "fileno", 0));
}

static mrb_value
mrb_bpf_sysopen(mrb_state *mrb, mrb_value klass)
{
  int i, sock;
  char path[16];

  sock = open("/dev/bpf", O_RDWR);
  if (sock == -1) {
    if (errno != ENOENT) {
      mrb_sys_fail(mrb, "cannot open bpf device");
    }
    sock = -1;
    for (i = 0; i < 256; i++) {
      snprintf(path, sizeof(path), "/dev/bpf%d", i);
      sock = open(path, O_RDWR);
      if (sock >= 0)
        break;
      if (errno != EBUSY) {
        mrb_sys_fail(mrb, "cannot open bpf device");
      }
    }
    if (sock == -1) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "no bpf device available");
    }
  }
  return mrb_fixnum_value(sock);
}

static mrb_value
mrb_bpf_get_buffer_length(mrb_state *mrb, mrb_value self)
{
  unsigned int blen;

  if (ioctl(socket_fd(mrb, self), BIOCGBLEN, &blen) == -1) {
    mrb_sys_fail(mrb, "BIOCGBLEN");
  }
  return mrb_fixnum_value(blen);
}

static mrb_value
mrb_bpf_get_header_complete(mrb_state *mrb, mrb_value self)
{
  unsigned int on;

  if (ioctl(socket_fd(mrb, self), BIOCGHDRCMPLT, &on) == -1) {
    mrb_sys_fail(mrb, "BIOCGHDRCMPLT");
  }
  return mrb_bool_value(on);
}

static mrb_value
mrb_bpf_get_interface(mrb_state *mrb, mrb_value self)
{
  struct ifreq ifr;
  mrb_int fd;

  fd = socket_fd(mrb, self);
  if (ioctl(fd, BIOCGETIF, &ifr) == -1) {
    mrb_sys_fail(mrb, "BIOCGETIF");
  }
  return mrb_str_new_cstr(mrb, ifr.ifr_name);
}

static mrb_value
mrb_bpf_get_seesent(mrb_state *mrb, mrb_value self)
{
#ifdef BIOCGSEESENT
  unsigned int on;

  if (ioctl(socket_fd(mrb, self), BIOCGSEESENT, &on) == -1) {
    mrb_sys_fail(mrb, "BIOCGSEESENT");
  }
  return mrb_bool_value(on);
#else
  mrb_raise(mrb, E_RUNTIME_ERROR, "BIOCGSEESENT is not supported on this system");
  return mrb_nil_value();
#endif
}

static mrb_value
mrb_bpf_set_buffer_length(mrb_state *mrb, mrb_value self)
{
  mrb_int n;
  unsigned int blen;

  mrb_get_args(mrb, "i", &n);
  blen = n;
  if (ioctl(socket_fd(mrb, self), BIOCSBLEN, &blen) == -1) {
    mrb_sys_fail(mrb, "BIOCSBLEN");
  }
  return mrb_fixnum_value(n);
}

static mrb_value
mrb_bpf_set_filter(mrb_state *mrb, mrb_value self)
{
  mrb_value str;
  u_int i, len = 0;
  char *cp, *line;
  struct bpf_program prog;
  struct bpf_insn *insns = NULL;

  mrb_get_args(mrb, "S", &str);
  cp = mrb_str_to_cstr(mrb, str);
  line = strsep(&cp, "\n");
  if (sscanf(line, "%u", &len) != 1)
    goto prog_err;
  insns = mrb_malloc(mrb, len * sizeof(struct bpf_insn));
  for (i = 0; i < len && cp != NULL; i++) {
    unsigned long k;
    line = strsep(&cp, "\n");
    if (sscanf(line, "%hu %hhu %hhu %lu", &insns[i].code, &insns[i].jt, &insns[i].jf, &k) != 4)
      goto prog_err;
    insns[i].k = k;
  }
  prog.bf_len = len;
  prog.bf_insns = insns;
  if (ioctl(socket_fd(mrb, self), BIOCSETF, &prog) == -1) {
    mrb_free(mrb, insns);
    mrb_sys_fail(mrb, "BIOCSETF");
  }

  mrb_free(mrb, insns);
  return mrb_nil_value();

prog_err:
  if (insns != NULL)
    mrb_free(mrb, insns);
  mrb_raise(mrb, E_RUNTIME_ERROR, "an error in BPF program");
  return mrb_nil_value();
}

static mrb_value
mrb_bpf_set_header_complete(mrb_state *mrb, mrb_value self)
{
  mrb_bool b;
  unsigned int on;

  mrb_get_args(mrb, "b", &b);
  on = b ? 1 : 0;
  if (ioctl(socket_fd(mrb, self), BIOCSHDRCMPLT, &on) == -1) {
    mrb_sys_fail(mrb, "BIOCSHDRCMPLT");
  }
  return mrb_bool_value(b);
}

static mrb_value
mrb_bpf_set_immediate(mrb_state *mrb, mrb_value self)
{
  mrb_bool b;
  unsigned int on;

  mrb_get_args(mrb, "b", &b);
  on = b ? 1 : 0;
  if (ioctl(socket_fd(mrb, self), BIOCIMMEDIATE, &on) == -1) {
    mrb_sys_fail(mrb, "BIOCIMMEDIATE");
  }
  return mrb_bool_value(b);
}

static mrb_value
mrb_bpf_set_interface(mrb_state *mrb, mrb_value self)
{
  struct ifreq ifr;
  mrb_value s;
  mrb_int len;

  mrb_get_args(mrb, "S", &s);
  len = RSTRING_LEN(s);
  if (len > sizeof(ifr.ifr_name)) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "too long interface name: %S", s);
  }

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, RSTRING_PTR(s), len);
  if (ioctl(socket_fd(mrb, self), BIOCSETIF, &ifr) == -1) {
    mrb_sys_fail(mrb, "BIOCSETIF");
  }
  return mrb_nil_value();
}

static mrb_value
mrb_bpf_set_promisc(mrb_state *mrb, mrb_value self)
{
  if (ioctl(socket_fd(mrb, self), BIOCPROMISC) == -1) {
    mrb_sys_fail(mrb, "BIOCPROMISC");
  }
  return mrb_nil_value();
}

static mrb_value
mrb_bpf_set_seesent(mrb_state *mrb, mrb_value self)
{
#ifdef BIOCSSEESENT
  mrb_bool b;
  unsigned int on;

  mrb_get_args(mrb, "b", &b);
  on = b ? 1 : 0;
  if (ioctl(socket_fd(mrb, self), BIOCSSEESENT, &on) == -1) {
    mrb_sys_fail(mrb, "BIOCSSEESENT");
  }
  return mrb_bool_value(b);
#else
  mrb_raise(mrb, E_RUNTIME_ERROR, "BIOCSSEESENT is not supported on this system");
  return mrb_nil_value();
#endif
}

static mrb_value
mrb_bpf_wordalign(mrb_state *mrb, mrb_value cls)
{
  mrb_int x;

  mrb_get_args(mrb, "i", &x);
  return mrb_fixnum_value(BPF_WORDALIGN(x));
}

void
mrb_mruby_bpf_gem_init(mrb_state *mrb)
{
  struct RClass *c;
  c = mrb_define_class(mrb, "BPF", mrb_class_get(mrb, "IO"));
  mrb_define_class_method(mrb, c, "_sysopen", mrb_bpf_sysopen, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, c, "wordalign", mrb_bpf_wordalign, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, c, "buffer_length", mrb_bpf_get_buffer_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "buffer_length=", mrb_bpf_set_buffer_length, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "header_complete", mrb_bpf_get_header_complete, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "header_complete=", mrb_bpf_set_header_complete, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "immediate=", mrb_bpf_set_immediate, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "interface", mrb_bpf_get_interface, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "interface=", mrb_bpf_set_interface, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "seesent", mrb_bpf_get_seesent, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "seesent=", mrb_bpf_set_seesent, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "set_filter", mrb_bpf_set_filter, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "set_promisc", mrb_bpf_set_promisc, MRB_ARGS_NONE());
}

void
mrb_mruby_bpf_gem_final(mrb_state *mrb)
{
}

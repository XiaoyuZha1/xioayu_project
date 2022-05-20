/*******************************************************************\

Module: C++ Language Type Checking

Author: Daniel Kroening, kroening@cs.cmu.edu

\*******************************************************************/

#ifndef CPROVER_CPP_DECLARATION_H
#define CPROVER_CPP_DECLARATION_H

#include <cassert>
#include <cpp/cpp_declarator.h>
#include <cpp/cpp_member_spec.h>
#include <cpp/cpp_storage_spec.h>
#include <cpp/cpp_template_args.h>
#include <cpp/cpp_template_type.h>

class cpp_declarationt : public exprt
{
public:
  typedef std::vector<cpp_declaratort> declaratorst;

  inline cpp_declarationt() : exprt("cpp-declaration")
  {
  }

  inline bool is_constructor() const
  {
    return type().id() == "constructor";
  }

  inline bool is_destructor() const
  {
    return type().id() == "destructor";
  }

  inline bool is_template() const
  {
    return get_bool("is_template");
  }

  inline bool is_class_template() const
  {
    return is_template() && type().id() == "struct" && declarators().empty();
  }

  inline const declaratorst &declarators() const
  {
    return (const declaratorst &)operands();
  }

  inline declaratorst &declarators()
  {
    return (declaratorst &)operands();
  }

  inline const cpp_storage_spect &storage_spec() const
  {
    return static_cast<const cpp_storage_spect &>(find("storage_spec"));
  }

  inline cpp_storage_spect &storage_spec()
  {
    return static_cast<cpp_storage_spect &>(add("storage_spec"));
  }

  inline const cpp_member_spect &member_spec() const
  {
    return static_cast<const cpp_member_spect &>(find("member_spec"));
  }

  inline cpp_member_spect &member_spec()
  {
    return static_cast<cpp_member_spect &>(add("member_spec"));
  }

  inline template_typet &template_type()
  {
    return static_cast<template_typet &>(add("template_type"));
  }

  inline const template_typet &template_type() const
  {
    return static_cast<const template_typet &>(find("template_type"));
  }

  inline cpp_template_args_non_tct &partial_specialization_args()
  {
    return static_cast<cpp_template_args_non_tct &>(
      add("partial_specialization_args"));
  }

  inline const cpp_template_args_non_tct &partial_specialization_args() const
  {
    return static_cast<const cpp_template_args_non_tct &>(
      find("partial_specialization_args"));
  }

  inline void set_specialization_of(const irep_idt &id)
  {
    set("specialization_of", id);
  }

  inline irep_idt get_specialization_of() const
  {
    return get("specialization_of");
  }

  void output(std::ostream &out) const;
};

extern inline cpp_declarationt &to_cpp_declaration(irept &irep)
{
  assert(irep.id() == "cpp-declaration");
  return static_cast<cpp_declarationt &>(irep);
}

extern inline const cpp_declarationt &to_cpp_declaration(const irept &irep)
{
  assert(irep.id() == "cpp-declaration");
  return static_cast<const cpp_declarationt &>(irep);
}

#endif

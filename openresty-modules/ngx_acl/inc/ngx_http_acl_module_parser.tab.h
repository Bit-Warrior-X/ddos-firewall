/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_NGX_HTTP_ACL_INC_NGX_HTTP_ACL_MODULE_PARSER_TAB_H_INCLUDED
# define YY_NGX_HTTP_ACL_INC_NGX_HTTP_ACL_MODULE_PARSER_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef NGX_HTTP_ACL_DEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define NGX_HTTP_ACL_DEBUG 1
#  else
#   define NGX_HTTP_ACL_DEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define NGX_HTTP_ACL_DEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined NGX_HTTP_ACL_DEBUG */
#if NGX_HTTP_ACL_DEBUG
extern int ngx_http_acl_debug;
#endif

/* Token kinds.  */
#ifndef NGX_HTTP_ACL_TOKENTYPE
# define NGX_HTTP_ACL_TOKENTYPE
  enum ngx_http_acl_tokentype
  {
    NGX_HTTP_ACL_EMPTY = -2,
    NGX_HTTP_ACL_EOF = 0,          /* "end of file"  */
    NGX_HTTP_ACL_error = 256,      /* error  */
    NGX_HTTP_ACL_UNDEF = 257,      /* "invalid token"  */
    token_id = 258,                /* token_id  */
    token_str = 259,               /* token_str  */
    token_index = 260,             /* token_index  */
    token_int = 261,               /* token_int  */
    keyword_id = 262,              /* keyword_id  */
    keyword_if = 263,              /* keyword_if  */
    keyword_do = 264,              /* keyword_do  */
    keyword_or = 265,              /* keyword_or  */
    keyword_allow = 266,           /* keyword_allow  */
    keyword_and = 267,             /* keyword_and  */
    keyword_matches = 268,         /* keyword_matches  */
    keyword_equals = 269,          /* keyword_equals  */
    token_break_line = 270,        /* token_break_line  */
    token_blank = 271,             /* token_blank  */
    keyword_not = 272,             /* keyword_not  */
    keyword_url = 273,             /* keyword_url  */
    keyword_contains = 274,        /* keyword_contains  */
    keyword_return = 275,          /* keyword_return  */
    keyword_query_string = 276,    /* keyword_query_string  */
    keyword_user_agent = 277,      /* keyword_user_agent  */
    keyword_belong_to = 278,       /* keyword_belong_to  */
    keyword_referer = 279,         /* keyword_referer  */
    keyword_client_ip = 280,       /* keyword_client_ip  */
    keyword_header_in = 281,       /* keyword_header_in  */
    keyword_sqli_detn = 282,       /* keyword_sqli_detn  */
    keyword_xss_detn = 283,        /* keyword_xss_detn  */
    keyword_cookie = 284           /* keyword_cookie  */
  };
  typedef enum ngx_http_acl_tokentype ngx_http_acl_token_kind_t;
#endif

/* Value type.  */
#if ! defined NGX_HTTP_ACL_STYPE && ! defined NGX_HTTP_ACL_STYPE_IS_DECLARED
union NGX_HTTP_ACL_STYPE
{
#line 53 "bison/parser.yacc"

    int             int_val;
    unsigned int    uint_val;
    char            id_val[256];
    char            str_val[256];
    void            (*push_op_code_pt)(UT_array* array);
    struct {
        int argc;
        void (*no_str_pt)(UT_array* array);
        void (*one_str_pt)(UT_array* array, char* str);
        char* argv[4];
    } push_str_code_info;

#line 115 "inc/ngx_http_acl_module_parser.tab.h"

};
typedef union NGX_HTTP_ACL_STYPE NGX_HTTP_ACL_STYPE;
# define NGX_HTTP_ACL_STYPE_IS_TRIVIAL 1
# define NGX_HTTP_ACL_STYPE_IS_DECLARED 1
#endif


extern NGX_HTTP_ACL_STYPE ngx_http_acl_lval;


int ngx_http_acl_parse (UT_array* array, ngx_pool_t* pool);


#endif /* !YY_NGX_HTTP_ACL_INC_NGX_HTTP_ACL_MODULE_PARSER_TAB_H_INCLUDED  */

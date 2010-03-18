/*
 Copyright 2009 Harald Weillechner, Daniel Lechner
 see COPYING file for details.
 ============================================================================
 Name        : moduleinfo.h
 Author      : Harald Weillechner, Daniel Lechner
 Version     : 0.0.4
 Licence     : GPL
 Description : global module informations
 ============================================================================
*/
/* Included *after* config.h, in order to re-define these macros */

#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "knxnetip"


#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
#define VERSION "0.0.4"



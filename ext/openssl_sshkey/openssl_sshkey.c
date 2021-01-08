/*
   Extend OpenSSL::PKey::EC::Point to provide #to_octet_string for use in Rubies that do not have it (except JRuby).
   https://ruby-doc.org/stdlib-2.6.6/libdoc/openssl/rdoc/OpenSSL/PKey/EC/Point.html#method-i-to_octet_string

   to_octet string was added in ruby/openssl 2.1.0
   - https://github.com/ruby/openssl/blob/master/History.md#version-210
   - https://github.com/ruby/openssl/pull/177

   Reference similar gems with extensions:
   - https://github.com/postageapp/openssl_pkcs8
   - https://github.com/onelogin/aead/issues/8
   - https://github.com/catharinejm/openssl_rsa_pss_verify

   Version indicators:
   - Of ruby/openssl
     - OpenSSL::VERSION (accessible from Ruby)

   - Of Ruby language
     - RUBY_VERSION (accessible from Ruby)
     - RUBY_API_VERSION_CODE (accessible from C)
       https://github.com/ruby/ruby/blob/master/include/ruby/version.h
       https://www.ruby-forum.com/t/c-api-version-functionality-detection/227925
     - ruby_version (in generated Makefile)

   - Of OpenSSL library
     - OPENSSL_VERSION_NUMBER layout 0xMNN00PPSL (accessible from C)
       https://github.com/openssl/openssl/blob/master/include/openssl/opensslv.h.in#L92-L102
*/


// https://github.com/postageapp/openssl_pkcs8/blob/master/ext/openssl_pkcs8/openssl_pkcs8.c#L1-L15
#include <ruby.h>
#include <ruby/version.h>  // required for RUBY_API_VERSION_CODE
#include <openssl/ssl.h>

// NOTE: GetECPoint and GetECGroup are used in Ruby 2.4 and above (which incorporates ruby/openssl 2.0 +)
// https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L27-L41
// Modification using RTYPEDDATA_TYPE from https://github.com/onelogin/aead/pull/10
#define GetECPoint(obj, point) do { \
    TypedData_Get_Struct(obj, EC_POINT, RTYPEDDATA_TYPE(obj), point); \
    if ((point) == NULL) \
	ossl_raise(eEC_POINT, "EC_POINT is not initialized"); \
} while (0)

#define GetECGroup(obj, group) do { \
    TypedData_Get_Struct(obj, EC_GROUP, RTYPEDDATA_TYPE(obj), group); \
    if ((group) == NULL) \
	ossl_raise(eEC_GROUP, "EC_GROUP is not initialized"); \
} while (0)

#define GetECPointGroup(obj, group) do { \
    VALUE _group = rb_attr_get(obj, id_i_group); \
    GetECGroup(_group, group); \
} while (0)

// NOTE: Get_EC_POINT and Get_EC_GROUP are used in Ruby 2.3 and below (which incorporates ruby/openssl 1.1)
// https://github.com/ruby/openssl/blob/8706e768540ab7d556f1859f71d7ee3c8b40e25d/ext/openssl/ossl_pkey_ec.c#L55-L86
// Modification using RTYPEDDATA_TYPE from https://github.com/onelogin/aead/pull/10
//
// NOTE: TypedData_Get_Struct is used in Ruby 2.2 and above
//       Data_Get_Struct is used in Ruby 2.1 and below
//       https://github.com/onelogin/aead/blob/340e7718d8bd9c1fcf3c443e32f439436ea2b70d/ext/openssl/cipher/aead/aead.c#L9-L17
#if RUBY_API_VERSION_CODE >= 20200
#define Get_EC_POINT(obj, p) do { \
    ossl_ec_point *ec_point; \
    TypedData_Get_Struct((obj), ossl_ec_point, RTYPEDDATA_TYPE(obj), ec_point); \
    if (ec_point == NULL) \
        ossl_raise(eEC_POINT, "missing ossl_ec_point structure"); \
    (p) = ec_point->point; \
} while(0)
#else
#define Get_EC_POINT(obj, p) do { \
    ossl_ec_point *ec_point; \
    Data_Get_Struct((obj), ossl_ec_point, ec_point); \
    if (ec_point == NULL) \
        ossl_raise(eEC_POINT, "missing ossl_ec_point structure"); \
    (p) = ec_point->point; \
} while(0)
#endif

#define Require_EC_POINT(obj, point) do { \
    Get_EC_POINT((obj), (point)); \
    if ((point) == NULL) \
        ossl_raise(eEC_POINT, "EC_POINT is not initialized"); \
} while(0)

#if RUBY_API_VERSION_CODE >= 20200
#define Get_EC_GROUP(obj, g) do { \
    ossl_ec_group *ec_group; \
    TypedData_Get_Struct((obj), ossl_ec_group, RTYPEDDATA_TYPE(obj), ec_group); \
    if (ec_group == NULL) \
        ossl_raise(eEC_GROUP, "missing ossl_ec_group structure"); \
    (g) = ec_group->group; \
} while(0)
#else
#define Get_EC_GROUP(obj, g) do { \
    ossl_ec_group *ec_group; \
    Data_Get_Struct((obj), ossl_ec_group, ec_group); \
    if (ec_group == NULL) \
        ossl_raise(eEC_GROUP, "missing ossl_ec_group structure"); \
    (g) = ec_group->group; \
} while(0)
#endif

#define Require_EC_GROUP(obj, group) do { \
    Get_EC_GROUP((obj), (group)); \
    if ((group) == NULL) \
        ossl_raise(eEC_GROUP, "EC_GROUP is not initialized"); \
} while(0)

// https://github.com/ruby/openssl/blob/8706e768540ab7d556f1859f71d7ee3c8b40e25d/ext/openssl/ossl_pkey_ec.c#L9-L17
typedef struct {
	EC_GROUP *group;
	int dont_free;
} ossl_ec_group;

typedef struct {
	EC_POINT *point;
	int dont_free;
} ossl_ec_point;

// https://github.com/ruby/openssl/blob/master/ext/openssl/ossl.h#L123
NORETURN(void ossl_raise(VALUE, const char *, ...));

// https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L43-L48
VALUE cEC;
VALUE cEC_GROUP;
VALUE eEC_GROUP;
VALUE cEC_POINT;
VALUE eEC_POINT;

// https://github.com/postageapp/openssl_pkcs8/blob/master/ext/openssl_pkcs8/openssl_pkcs8.c#L17-L18
VALUE mOSSL;
VALUE mPKey;

// Added
VALUE cPKey;
VALUE sOSSLVersion;

// https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L57-L61
static ID ID_uncompressed;
static ID ID_compressed;
static ID ID_hybrid;
static ID id_i_group;

// https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_bn.c#L158
BN_CTX *ossl_bn_ctx;

// https://stackoverflow.com/a/56241323
int compVersions ( const char * version1, const char * version2 ) {
    unsigned major1 = 0, minor1 = 0, bugfix1 = 0;
    unsigned major2 = 0, minor2 = 0, bugfix2 = 0;

    sscanf(version1, "%u.%u.%u", &major1, &minor1, &bugfix1);
    sscanf(version2, "%u.%u.%u", &major2, &minor2, &bugfix2);

    if (major1 < major2) return -1;
    if (major1 > major2) return 1;
    if (minor1 < minor2) return -1;
    if (minor1 > minor2) return 1;
    if (bugfix1 < bugfix2) return -1;
    if (bugfix1 > bugfix2) return 1;

    return 0;
}

// https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L970-L984
static point_conversion_form_t
parse_point_conversion_form_symbol(VALUE sym)
{
    ID id = SYM2ID(sym);

    if (id == ID_uncompressed)
	return POINT_CONVERSION_UNCOMPRESSED;
    else if (id == ID_compressed)
	return POINT_CONVERSION_COMPRESSED;
    else if (id == ID_hybrid)
	return POINT_CONVERSION_HYBRID;
    else
	ossl_raise(rb_eArgError, "unsupported point conversion form %+"PRIsVALUE
		   " (expected :compressed, :uncompressed, or :hybrid)", sym);
}

// ossl_ec_point_to_octet_string https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1403-L1437
// EC_POINT_point2oct            https://github.com/openssl/openssl/blob/master/crypto/ec/ec_oct.c#L73-L102
/* ec_GF2m_simple_point2oct      https://github.com/openssl/openssl/blob/master/crypto/ec/ec2_oct.c#L120-L249

 * call-seq:
 *    point.to_octet_string(conversion_form) -> String
 *
 * Returns the octet string representation of the elliptic curve point.
 *
 * _conversion_form_ specifies how the point is converted. Possible values are:
 *
 * - +:compressed+
 * - +:uncompressed+
 * - +:hybrid+
 */
static VALUE
ossl_ec_point_to_octet_string(VALUE self, VALUE conversion_form)
{
    EC_POINT *point;
    const EC_GROUP *group;
    point_conversion_form_t form;
    VALUE str;
    size_t len;

    //----------------------------------------------
    // BEGIN NONSTANDARD SECTION
    int version_comparison;
    char *ossl_version;
    VALUE group_v;
    
    // Force compilation error if ruby/version.h is not included
#ifndef RUBY_API_VERSION_CODE
    RUBY_API_VERSION_CODE;
#endif

    // Obtain ruby/openssl version from OpenSSL::VERSION
    ossl_version = StringValueCStr(sOSSLVersion);

    version_comparison = compVersions(ossl_version, "2.0.0");
    if (version_comparison >= 0) {
        // ruby/openssl 2.0 and above (in Ruby 2.4 and above)
        // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1424-L1425
        GetECPoint(self, point);
        GetECPointGroup(self, group);
    }

    else {
        // ruby/openssl 1.1 (in Ruby 2.3 and below)
        // https://github.com/ruby/openssl/blob/8706e768540ab7d556f1859f71d7ee3c8b40e25d/ext/openssl/ossl_pkey_ec.c#L1482
        group_v = rb_iv_get(self, "@group");

        // https://github.com/ruby/openssl/blob/8706e768540ab7d556f1859f71d7ee3c8b40e25d/ext/openssl/ossl_pkey_ec.c#L1487-L1488
        Require_EC_POINT(self, point);
        Require_EC_GROUP(group_v, group);
    }
    // END NONSTANDARD SECTION
    //----------------------------------------------

    form = parse_point_conversion_form_symbol(conversion_form);

    len = EC_POINT_point2oct(group, point, form, NULL, 0, ossl_bn_ctx);
    if (!len)
	ossl_raise(eEC_POINT, "EC_POINT_point2oct");
    str = rb_str_new(NULL, (long)len);
    if (!EC_POINT_point2oct(group, point, form,
			    (unsigned char *)RSTRING_PTR(str), len,
			    ossl_bn_ctx))
	ossl_raise(eEC_POINT, "EC_POINT_point2oct");

    return str;
}

void
Init_openssl_sshkey(void) {

    // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1600-L1602
    ID_uncompressed = rb_intern("uncompressed");
    ID_compressed = rb_intern("compressed");
    ID_hybrid = rb_intern("hybrid");

    // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1701
    id_i_group = rb_intern("@group");

    // module OpenSSL
    mOSSL = rb_const_get(rb_cObject, rb_intern("OpenSSL"));   // https://github.com/postageapp/openssl_pkcs8/blob/master/ext/openssl_pkcs8/openssl_pkcs8.c#L181

    // module OpenSSL
    //   VERSION = "2.2.0"
    sOSSLVersion = rb_const_get(mOSSL, rb_intern("VERSION"));

    // module OpenSSL
    //   module PKey
    mPKey = rb_const_get(mOSSL, rb_intern("PKey"));           // https://github.com/postageapp/openssl_pkcs8/blob/master/ext/openssl_pkcs8/openssl_pkcs8.c#L182

    // module OpenSSL
    //   module PKey
    //     class Pkey
    cPKey = rb_const_get(mPKey, rb_intern("PKey"));           // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1565

    // module OpenSSL
    //   module PKey
    //     class EC
    cEC = rb_const_get(mPKey, rb_intern("EC"));               // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1587

    // module OpenSSL
    //   module PKey
    //     class Pkey
    //       class EC
    //         class Point
    cEC_POINT = rb_const_get(cEC, rb_intern("Point"));        // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1589

    // module OpenSSL
    //   module PKey
    //     class Pkey
    //       class EC
    //         class Group
    cEC_GROUP = rb_const_get(cEC, rb_intern("Group"));        // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1588

    // module OpenSSL
    //   module PKey
    //     class Pkey
    //       class EC
    //         class Point
    //           class Error
    eEC_POINT = rb_const_get(cEC_POINT, rb_intern("Error"));  // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1591

    // module OpenSSL
    //   module PKey
    //     class Pkey
    //       class EC
    //         class Group
    //           class Error
    eEC_GROUP = rb_const_get(cEC_GROUP, rb_intern("Error"));  // https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_ec.c#L1590

    // to_octet_string
    rb_define_method(cEC_POINT, "to_octet_string_extension", ossl_ec_point_to_octet_string, 1);
}


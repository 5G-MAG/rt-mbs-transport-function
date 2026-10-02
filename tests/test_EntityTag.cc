/*****************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: entity-tag formatting tests
 *****************************************************************************
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <iostream>
#include <string>

#include "EntityTag.hh"

MBSTF_NAMESPACE_USING;

static int pass = 0;
static int fail = 0;

static void check(bool ok, const std::string &name)
{
    if (ok) { pass++; std::cout<<"INFO: "<<name<<" passed."<<std::endl; }
    else    { fail++; std::cout<<"ERROR: "<<name<<" failed."<<std::endl; }
}

/* RFC 9110 section 8.8.3: "opaque-tag = DQUOTE *etagc DQUOTE". A bare digest, which is what
   the resource layer computes, is not a legal field value until it is quoted. */
static void testBareDigestIsQuoted()
{
    check(entityTagQuoted("0d0fccda46707c49") == "\"0d0fccda46707c49\"", "testBareDigestIsQuoted");
}

/* Quoting a value that already carries its quotes would emit "" around "", which no
   comparison against a client's If-Match value can match. */
static void testAlreadyQuotedIsUnchanged()
{
    check(entityTagQuoted("\"abc\"") == "\"abc\"", "testAlreadyQuotedIsUnchanged");
}

static void testWeakBareIsQuotedKeepingTheIndicator()
{
    check(entityTagQuoted("W/abc") == "W/\"abc\"", "testWeakBareIsQuotedKeepingTheIndicator");
}

static void testWeakQuotedIsUnchanged()
{
    check(entityTagQuoted("W/\"abc\"") == "W/\"abc\"", "testWeakQuotedIsUnchanged");
}

/* An empty opaque-tag is legal: *etagc admits zero characters. */
static void testEmptyTagBecomesEmptyQuotedTag()
{
    check(entityTagQuoted("") == "\"\"", "testEmptyTagBecomesEmptyQuotedTag");
}

/* A lone quote is not a quoted tag; treating it as one would drop the only character. */
static void testSingleQuoteCharacterIsQuoted()
{
    check(entityTagQuoted("\"") == "\"\"\"", "testSingleQuoteCharacterIsQuoted");
}

static void testOpaqueStripsQuotes()
{
    check(entityTagOpaque("\"abc\"") == "abc", "testOpaqueStripsQuotes");
}

static void testOpaqueStripsWeakIndicatorAndQuotes()
{
    check(entityTagOpaque("W/\"abc\"") == "abc", "testOpaqueStripsWeakIndicatorAndQuotes");
}

/* Weak and strong forms of the same tag share an opaque-tag, which is what makes the
   weak comparison in RFC 9110 section 8.8.3.2 possible at all. */
static void testWeakAndStrongShareTheirOpaqueTag()
{
    check(entityTagOpaque("W/\"abc\"") == entityTagOpaque("\"abc\""),
          "testWeakAndStrongShareTheirOpaqueTag");
}

static void testOpaqueOfABareTagIsItself()
{
    check(entityTagOpaque("abc") == "abc", "testOpaqueOfABareTagIsItself");
}

/* Round trip: whatever the resource layer holds, quoting it then taking the opaque part
   must return what it started with. */
static void testQuoteThenOpaqueRoundTrips()
{
    bool ok = true;
    for (const auto &tag : {std::string("abc"), std::string("\"abc\""), std::string("W/abc"),
                            std::string("W/\"abc\""), std::string("")}) {
        if (entityTagOpaque(entityTagQuoted(tag)) != entityTagOpaque(tag)) ok = false;
    }
    check(ok, "testQuoteThenOpaqueRoundTrips");
}

int main()
{
    std::cout<<"### EntityTag: Test start #### "<<std::endl;
    testBareDigestIsQuoted();
    testAlreadyQuotedIsUnchanged();
    testWeakBareIsQuotedKeepingTheIndicator();
    testWeakQuotedIsUnchanged();
    testEmptyTagBecomesEmptyQuotedTag();
    testSingleQuoteCharacterIsQuoted();
    testOpaqueStripsQuotes();
    testOpaqueStripsWeakIndicatorAndQuotes();
    testWeakAndStrongShareTheirOpaqueTag();
    testOpaqueOfABareTagIsItself();
    testQuoteThenOpaqueRoundTrips();
    std::cout<<"Test: EntityTag Pass: "<<pass<<" Fail: "<<fail<<std::endl;
    std::cout<<"### EntityTag: Test finish #### "<<std::endl;
    return fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

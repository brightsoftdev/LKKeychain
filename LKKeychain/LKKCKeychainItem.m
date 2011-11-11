//
//  LKKCKeychainItem.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Security/Security.h>
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCKeychain.h"
#import "LKKCUtil.h"
#import "LKKCGenericPassword.h"
#import "LKKCInternetPassword.h"
#import "LKKCCertificate.h"
#import "LKKCIdentity.h"
#import "LKKCKey.h"

static CFMutableDictionaryRef knownItemClasses;

@implementation LKKCKeychainItem
{
    SecKeychainItemRef _sitem;
    NSMutableDictionary *_attributes;
    NSMutableDictionary *_updatedAttributes;
}

+ (void)registerSubclass:(Class)cls
{
    if (knownItemClasses == nil) {
        knownItemClasses = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, 
                                                     &kCFTypeDictionaryKeyCallBacks, NULL);
    }
    CFDictionarySetValue(knownItemClasses, [cls itemClass], cls);
}

- (id)initWithSecKeychainItem:(SecKeychainItemRef)sitem attributes:(NSDictionary *)attributes 
{
    self = [super init];
    if (self == nil)
        return nil;
    CFRetain(sitem);
    _sitem = sitem;
    if (attributes != nil) {
        _attributes = [attributes mutableCopy];
    }
    return self;
}

- (void)dealloc
{
    if (_sitem != NULL) {
        CFRelease(_sitem);
        _sitem = NULL;
    }
    if (_attributes != nil) {
        [_attributes release];
        _attributes = nil;
    }
    if (_updatedAttributes != nil) {
        [_updatedAttributes release];
        _updatedAttributes = nil;
    }
    [super dealloc];
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@ %p>", [self className], self];
}

#pragma mark - Factory methods

+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem attributes:(NSDictionary *)attributes error:(NSError **)error
{
    Class cls = CFDictionaryGetValue(knownItemClasses, itemClass);
    if (cls == NULL)
        cls = [LKKCKeychainItem class];
    
    id item = [[cls alloc] initWithSecKeychainItem:sitem attributes:attributes];
    return [item autorelease];
}

+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem error:(NSError **)error
{
    return [LKKCKeychainItem itemWithClass:itemClass SecKeychainItem:sitem attributes:nil error:error];
}

+ (id)itemWithClass:(CFTypeRef)itemClass persistentID:(NSData *)persistentID error:(NSError **)error
{
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           itemClass, kSecClass,
                           [NSArray arrayWithObject:(id)persistentID], kSecMatchItemList,
                           kCFBooleanTrue, kSecReturnRef,
                           kCFBooleanTrue, kSecReturnAttributes,
                           kSecMatchLimitOne, kSecMatchLimit,
                           nil];
    NSDictionary *result = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status) {
        LKKCReportError(status, error, @"Can't resolve persistent ID");
        return nil;
    }
    
    [result autorelease];
    SecKeychainItemRef sitem = (SecKeychainItemRef)[result objectForKey:(id)kSecValueRef];
    return [self itemWithClass:itemClass SecKeychainItem:sitem attributes:result error:error];
}

#pragma mark -

+ (CFTypeRef)itemClass
{
    [NSException raise:NSInternalInconsistencyException format:@"Unknown item class"];
    return NULL;
}

#pragma mark - Attributes

- (NSDictionary *)attributes 
{
    NSAssert(_sitem, @"Item deleted");
    if (_attributes == nil) {
        NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                               [[self class] itemClass], kSecClass,
                               [NSArray arrayWithObject:(id)_sitem], kSecMatchItemList,
                               kCFBooleanTrue, kSecReturnAttributes,
                               kSecMatchLimitOne, kSecMatchLimit,
                               nil];
        NSDictionary *attrs = nil;
        OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&attrs);
        if (status) {
            LKKCReportError(status, NULL, @"Can't query item attributes");
            return nil;
        }
        _attributes = [attrs mutableCopy];
        [attrs release];
        if (_updatedAttributes != nil) {
            [_attributes addEntriesFromDictionary:_updatedAttributes];
        }
    }
    return _attributes;
}

- (void)setAttribute:(CFTypeRef)attribute toValue:(CFTypeRef)value 
{
    NSAssert(_sitem, @"Item deleted");

    if (_updatedAttributes == nil) {
        _updatedAttributes = [[NSMutableDictionary alloc] init];
    }
    if (value == nil)
        value = [NSNull null];
    [(NSMutableDictionary *)self.attributes setObject:value forKey:attribute];
    [_updatedAttributes setObject:value forKey:attribute];
}

#pragma mark - Properties

- (SecKeychainItemRef)SecKeychainItem
{
    return _sitem;
}

- (NSData *)persistentID
{
    NSAssert(_sitem, @"Item deleted");
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           [[self class] itemClass], kSecClass,
                           [NSArray arrayWithObject:(id)_sitem], kSecMatchItemList,
                           kCFBooleanTrue, kSecReturnPersistentRef,
                           kSecMatchLimitOne, kSecMatchLimit,
                           nil];
    NSData *persistentID = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&persistentID);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get persistent reference to item");
        return nil;
    }
    return [persistentID autorelease];
}

- (NSData *)rawData
{
    NSAssert(_sitem, @"Item deleted");
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           [[self class] itemClass], kSecClass,
                           [NSArray arrayWithObject:(id)_sitem], kSecMatchItemList,
                           kCFBooleanTrue, kSecReturnData,
                           kSecMatchLimitOne, kSecMatchLimit,
                           nil];
    NSData *data = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&data);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get raw data of item");
        return nil;
    }
    return [data autorelease];
}

- (void)setRawData:(NSData *)rawData
{
    [self setAttribute:kSecValueData toValue:rawData];
}

- (LKKCKeychain *)keychain
{
    NSAssert(_sitem, @"Item deleted");

    OSStatus status;
    SecKeychainRef skeychain = NULL;
    status = SecKeychainItemCopyKeychain(_sitem, &skeychain);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get keychain for item");
        return nil;
    }
    LKKCKeychain *keychain = [LKKCKeychain keychainWithSecKeychain:skeychain];
    CFRelease(skeychain);
    return keychain;
}

#pragma mark - Operations

- (BOOL)saveItemWithError:(NSError **)error
{
    NSAssert(_sitem, @"Item deleted");
    if (_updatedAttributes == nil || [_updatedAttributes count] == 0) {
        return YES;
    }
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           [[self class] itemClass], kSecClass,
                           [NSArray arrayWithObject:(id)_sitem], kSecMatchItemList,
                           nil];
    OSStatus status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)_updatedAttributes);
    if (status) {
        LKKCReportError(status, error, @"Can't update item attributes");
        return NO;
    }
    [_updatedAttributes release];
    _updatedAttributes = nil;
    [self revertItem];
    return YES;
}

- (void)revertItem 
{
    NSAssert(_sitem, @"Item deleted");
    if (_updatedAttributes) {
        [_updatedAttributes release];
        _updatedAttributes = nil;
    }
    if (_attributes) {
        [_attributes release];
        _attributes = nil;
    }
}

- (BOOL)deleteItemWithError:(NSError **)error
{
    NSAssert(_sitem, @"Item already deleted");
    CFTypeRef itemClass = [self.attributes objectForKey:kSecClass];
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           itemClass, kSecClass,
                           [NSArray arrayWithObject:(id)_sitem], kSecMatchItemList,
                           kSecMatchLimitOne, kSecMatchLimit,
                           nil];    
    OSStatus status = SecItemDelete((CFDictionaryRef)query);
    if (status) {
        LKKCReportError(status, error, @"Can't delete keychain item");
        return NO;
    }
    CFRelease(_sitem);
    _sitem = NULL;
    return YES;
}
@end

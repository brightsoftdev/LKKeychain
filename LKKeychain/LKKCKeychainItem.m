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
    // _sitem may be null for freshly created passwords that aren't on a keychain yet.
    // Deleted items have _sitem, _attributes and _updatedAttributes set to nil.
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
    if (sitem != NULL) {
        CFRetain(sitem);
        _sitem = sitem;
    }
 
    if (attributes != nil) {
        _attributes = [attributes mutableCopy];
        [_attributes removeObjectForKey:kSecValueData];
        [_attributes removeObjectForKey:kSecValuePersistentRef];
        [_attributes removeObjectForKey:kSecValueRef];
    }
    else if (sitem == NULL) {
        _attributes = [[NSMutableDictionary alloc] init];
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
    if (_attributes == nil) {
        if (_sitem == NULL)
            return nil;
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
    if (_sitem == nil && _attributes == nil) {
        [NSException raise:NSInvalidArgumentException format:@"Can't set attributes on deleted items"];
    }
    if (_updatedAttributes == nil) {
        _updatedAttributes = [[NSMutableDictionary alloc] init];
    }
    if (_attributes == nil) {
        [self attributes];
    }
    NSAssert(_attributes != nil, @"");
    if (value == nil)
        value = [NSNull null];
    [_attributes setObject:value forKey:attribute];
    [_updatedAttributes setObject:value forKey:attribute];
}

#pragma mark - Properties

- (SecKeychainItemRef)SecKeychainItem
{
    return _sitem;
}

- (NSData *)persistentID
{
    if (_sitem == NULL)
        return nil;
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
    NSData *data = [self.attributes objectForKey:kSecValueData];
    if (data != nil)
        return data;
    if (_sitem == NULL)
        return nil;
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           [[self class] itemClass], kSecClass,
                           [NSArray arrayWithObject:(id)_sitem], kSecMatchItemList,
                           kCFBooleanTrue, kSecReturnData,
                           kSecMatchLimitOne, kSecMatchLimit,
                           nil];
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
    if (_sitem == NULL)
        return nil;
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
    if (_sitem == nil) {
        [NSException raise:NSInvalidArgumentException format:@"Can't save items that aren't on a keychain"];
    }
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
    if (_sitem == NULL)
        return;
    if (_updatedAttributes) {
        [_updatedAttributes release];
        _updatedAttributes = nil;
    }
    if (_attributes) {
        [_attributes release];
        _attributes = nil;
    }
}

- (BOOL)addToKeychain:(LKKCKeychain *)keychain error:(NSError **)error
{
    if (_sitem == NULL && _attributes == NULL) {
        [NSException raise:NSInvalidArgumentException format:@"Can't add deleted items to keychains"];
    }
    SecKeychainRef skeychain = keychain.SecKeychain;
    if (skeychain == NULL) {
        [NSException raise:NSInvalidArgumentException format:@"Keychain must not be zero"];
    }
        
    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    if (_sitem != NULL) {
        [attributes setObject:[NSArray arrayWithObject:(id)_sitem] forKey:kSecUseItemList];
    }
    else {
        [attributes addEntriesFromDictionary:_attributes];
    }
    [attributes setObject:[[self class] itemClass] forKey:kSecClass];
    [attributes setObject:(id)skeychain forKey:kSecUseKeychain]; // Private in 10.6
    [attributes setObject:[NSNumber numberWithBool:YES] forKey:kSecReturnRef];
    
    SecKeychainItemRef result = nil;
    OSStatus status = SecItemAdd((CFDictionaryRef)attributes, (CFTypeRef *)&result);
    if (status) {
        LKKCReportError(status, error, @"Can't add keychain item");
        return NO;
    }
    
    if (_sitem != NULL) {
        CFRelease(_sitem);
        _sitem = result; // pass ownership; retain isn't necessary
        if (![self saveItemWithError:error]) {
            [self revertItem];
            return NO;
        }
    }
    else { // _sitem was NULL
        _sitem = result; // pass ownership; retain isn't necessary
    }
    [self revertItem];
    return YES;
}

- (BOOL)deleteItemWithError:(NSError **)error
{
    if (_sitem == NULL)
        return YES;
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           [[self class] itemClass], kSecClass,
                           [NSArray arrayWithObject:(id)_sitem], kSecMatchItemList,
                           kSecMatchLimitOne, kSecMatchLimit,
                           nil];    
    OSStatus status = SecItemDelete((CFDictionaryRef)query);
    if (status) {
        LKKCReportError(status, error, @"Can't delete keychain item");
        return NO;
    }
    // The keychain query functions like to crash if we don't release deleted items immediately.
    CFRelease(_sitem);
    _sitem = NULL;
    [_updatedAttributes release];
    _updatedAttributes = nil;
    [_attributes release];
    _attributes = nil;
    return YES;
}

- (BOOL)isDeleted
{
    return _sitem == NULL && _attributes == nil;
}
@end

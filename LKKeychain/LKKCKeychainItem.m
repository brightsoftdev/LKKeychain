//
//  LKKCKeychainItem.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
//  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL KÁROLY LŐRENTEY BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

@interface LKKCKeychainItem()
@property (nonatomic, readonly) NSDictionary *attributes;
@end

@implementation LKKCKeychainItem

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
        _attributesFilled = YES;
    }
    else if (sitem == NULL) {
        _attributes = [[NSMutableDictionary alloc] init];
        _attributesFilled = YES;
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

+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem attributes:(NSDictionary *)attributes
{
    Class cls = CFDictionaryGetValue(knownItemClasses, itemClass);
    if (cls == NULL)
        cls = [LKKCKeychainItem class];
    
    id item = [[cls alloc] initWithSecKeychainItem:sitem attributes:attributes];
    return [item autorelease];
}

+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem
{
    return [LKKCKeychainItem itemWithClass:itemClass SecKeychainItem:sitem attributes:nil];
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
    return [self itemWithClass:itemClass SecKeychainItem:sitem attributes:result];
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
    if (_attributes == nil && !_attributesFilled) {
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
            if (status != errSecItemNotFound) {
                LKKCReportError(status, NULL, @"Can't query item attributes");
            }
            _attributesFilled = YES;
            return nil;
        }
        _attributes = [attrs mutableCopy];
        [attrs release];
        if (_updatedAttributes != nil) {
            [_attributes addEntriesFromDictionary:_updatedAttributes];
        }
        _attributesFilled = YES;
    }
    return _attributes;
}

- (id)valueForAttribute:(CFTypeRef)attribute
{
    id value = [_updatedAttributes valueForKey:attribute];
    if (value == nil)
        value = [self.attributes valueForKey:attribute];
    if (value == [NSNull null])
        return nil;
    return value;
}

- (void)setAttribute:(CFTypeRef)attribute toValue:(CFTypeRef)value 
{
    if (_sitem == nil && _attributes == nil) {
        [NSException raise:NSInvalidArgumentException format:@"Can't set attributes on deleted items"];
    }
    if (_updatedAttributes == nil) {
        _updatedAttributes = [[NSMutableDictionary alloc] init];
    }
    if (value == nil)
        value = [NSNull null];
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
        if (status != errSecItemNotFound) {
            LKKCReportError(status, NULL, @"Can't get persistent reference to item");
        }
        return nil;
    }
    return [persistentID autorelease];
}

- (NSData *)rawData
{
    return [self rawDataWithError:NULL];
}

- (NSData *)rawDataWithError:(NSError **)error
{
    NSData *data = [self valueForAttribute:kSecValueData];
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
    if (!status)
        return [data autorelease];
    
    UInt32 slength = 0;
    void *sdata = NULL;
    status = SecKeychainItemCopyAttributesAndData(_sitem, NULL, NULL, NULL, &slength, &sdata);
    if (status) {
        LKKCReportError(status, error, @"Can't get item data");
        return nil;
    }
    data = [NSData dataWithBytes:sdata length:slength];
    SecKeychainItemFreeAttributesAndData(NULL, sdata);
    return data;
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
        if (status != errSecNoSuchKeychain) {
            LKKCReportError(status, NULL, @"Can't get keychain for item");
        }
        return nil;
    }
    LKKCKeychain *keychain = [LKKCKeychain keychainWithSecKeychain:skeychain];
    CFRelease(skeychain);
    return keychain;
}

#pragma mark - Operations

- (BOOL)saveItemWithError:(NSError **)error
{
    OSStatus status;
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
    status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)_updatedAttributes);
    if (status) {
        LKKCReportError(status, error, @"Can't update item attributes");
        return NO;
    }
    [_updatedAttributes release];
    _updatedAttributes = nil;
    [self revertItem];
    [self attributes];
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
    _attributesFilled = NO;
}

- (SecAccessRef)access
{
    return NULL;
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
    
    BOOL needsSave = NO;
    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    if (_sitem != NULL) {
        [attributes setObject:[NSArray arrayWithObject:(id)_sitem] forKey:kSecUseItemList];
        if (self.keychain == nil) 
            [attributes addEntriesFromDictionary:_updatedAttributes];
        needsSave = YES;
    }
    else {
        [attributes addEntriesFromDictionary:_updatedAttributes];
    }
    [attributes setObject:[[self class] itemClass] forKey:kSecClass];
    [attributes setObject:(id)skeychain forKey:kSecUseKeychain]; // Private in 10.6
    SecAccessRef saccess = [self access];
    if (saccess != NULL) {
        [attributes setObject:(id)saccess forKey:kSecAttrAccess];
    }
    [attributes setObject:[NSNumber numberWithBool:YES] forKey:kSecReturnRef];

    CFTypeRef result = NULL;
    OSStatus status = SecItemAdd((CFDictionaryRef)attributes, &result);
    if (status) {
        LKKCReportError(status, error, @"Can't add keychain item");
        return NO;
    }
    
    if (_sitem != NULL)
        CFRelease(_sitem);
    if (CFGetTypeID(result) == CFArrayGetTypeID()) {
        if (CFArrayGetCount(result) != 1) {
            LKKCReportError(errSecMultipleValuesUnsupported, error, @"SecItemAdd returned multiple items");
            CFRelease(result);
            return NO;
        }
        _sitem = (SecKeychainItemRef)CFRetain(CFArrayGetValueAtIndex(result, 0));
    }
    else {
        _sitem = (SecKeychainItemRef)CFRetain(result);
    }
    CFRelease(result);
    
    if (needsSave && ![self saveItemWithError:error]) {
        [self revertItem];
        [self attributes];
        return NO;
    }
    [self revertItem];
    [self attributes];
    return YES;
}

- (BOOL)deleteItemWithError:(NSError **)error
{
    if (_sitem == NULL)
        return YES;
    // Don't use SecItemDelete; it doesn't actually delete keys that have more than one application with decrypt rights.
    OSStatus status = SecKeychainItemDelete(_sitem);
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
    _attributesFilled = YES;
    return YES;
}

- (BOOL)isDeleted
{
    return _sitem == NULL && _attributes == nil;
}
@end

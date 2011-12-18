//
//  LKKCKeychainItem.h
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

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class LKKCKeychain;

/** `LKKCKeychainItem` is an abstract class that represents items that can be added to a keychain.
 
 The following concrete subclasses are available:
 
 - <LKKCGenericPassword> represents generic passwords.
 - <LKKCInternetPassword> represents internet passwords.
 - <LKKCCertificate> represents certificates.
 - <LKKCKey> represents cryptographic keys.
 - <LKKCIdentity> is a pseudo-item representing identities.
 */
@interface LKKCKeychainItem : NSObject
{
@protected
    // Deleted items have _sitem, _attributes and _updatedAttributes set to nil.
    // New passwords may also have a nil _sitem, but their _attributes is non-nil.
    SecKeychainItemRef _sitem;
    NSMutableDictionary *_attributes;
    NSMutableDictionary *_updatedAttributes;
    BOOL _attributesFilled;
}

/** Returns the persistent ID for this item.
 
 Persistent IDs are opaque data objects that can be used to retrieve a particular keychain item.
 They only work on the system on which they were created, but can be used as long as the item isn't deleted.
 
 Note that changing a primary key attribute of a keychain item will invalidate its previous persistent ID.
 
 @return The persistent ID for this item.
 @see +[LKKCKeychain genericPasswordWithPersistentID:]
 @see +[LKKCKeychain internetPasswordWithPersistentID:]
 @see +[LKKCKeychain certificateWithPersistentID:]
 @see +[LKKCKeychain keyWithPersistentID:]
 */
@property (nonatomic, readonly) NSData *persistentID;

/** The raw data of this item, or nil of the data is not accessible.

 This property is provided for completeness, but it is generally a better idea to use the class-specific properties provided by subclasses.
 
 The format and availability of this data depends on the class of the item and how it was imported into the keychain. 
 @see -[LKKCGenericPassword password]
 @see -[LKKCInternetPassword password]
 @see -[LKKCCertificate data]
 @see -[LKKCKey keyDataWithError:]
 */
@property (nonatomic, copy) NSData *rawData;

/** Returns the raw data of this item, or nil of the data is not accessible.
 
 This property is provided for completeness, but it is generally a better idea to use the class-specific properties provided by subclasses.
 
 The format and availability of this data depends on the class of the item and how it was imported into the keychain. 
 @param error On output, the error that occurred in case the data could not be accessed (optional).
 @return The raw data that is stored by this item, or nil if an error happened.
 @see -[LKKCGenericPassword password]
 @see -[LKKCInternetPassword password]
 @see -[LKKCCertificate data]
 @see -[LKKCKey keyDataWithError:]
 */
- (NSData *)rawDataWithError:(NSError **)error;

/** The keychain on which this item is saved. Nil when this item isn't on a keychain. */
@property (nonatomic, readonly) LKKCKeychain *keychain;

/** The underlying `SecKeychainItem` reference. */
@property (nonatomic, readonly) SecKeychainItemRef SecKeychainItem;

/** Save previous modifications to this item's properties to the keychain. 
 @param error On output, the error that occurred in case the item could not be saved (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 */
- (BOOL)saveItemWithError:(NSError **)error;

/** Reverts unsaved modifications to this item's properties.
 */
- (void)revertItem;

/** Add this item to a keychain. The item's state is refreshed to reflect the change.
 @param keychain The keychain to which to add this item.
 @param error On output, the error that occurred in case the item could not be added to _keychain_ (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 */
- (BOOL)addToKeychain:(LKKCKeychain *)keychain error:(NSError **)error;

/** Delete item from its keychain, and invalidate this object. 
 @param error On output, the error that occurred in case the item could not be deleted (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 */
- (BOOL)deleteItemWithError:(NSError **)error;

/** Returns whether this item has been deleted.
 @return YES if this item has been deleted with <deleteItemWithError:>.
 */
- (BOOL)isDeleted;

@end

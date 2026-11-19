// RosKenorRedirect.m
// Combined NSURLProtocol (NSURLConnection + NSURLSession), CFNetwork,
// libcurl (curl_easy_setopt via fishhook), and BSD connect() + SecTrust
// interceptor for Rules of Survival (Ros Kenor).
//
// Compile on macOS with Xcode CLI tools:
//   clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//     -miphoneos-version-min=12.0 -shared -fobjc-arc -Wno-deprecated-declarations \
//     -framework Foundation -framework UIKit -framework QuartzCore -framework WebKit -framework Security -framework CFNetwork \
//     -install_name @executable_path/Frameworks/RosKenorRedirect.dylib \
//     -o RosKenorRedirect.dylib \
//     RoS_Server_backend/tools/RosKenorRedirect.m RoS_Server_backend/tools/fishhook.c

#import <CFNetwork/CFNetwork.h>
#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "fishhook.h"
#include "ros_assets_data.h"

static NSString *const kRosKenorBaseURL = @"https://api.stillchooseyou.site";
static NSString *const kHandledKey = @"RosKenorRedirectHandled";

static const char *kOldServerIP = "172.65.54.209";
static const char *kAltGameIP = "172.104.170.200";
static const char *kNeteaseEdgeIP = "223.252.216.48";
static const char *kLocalGatewayIP = "192.168.8.42";
static const uint16_t kLocalHttpsPort = 8443;
// __isPlatformVersionAtLeast is emitted by Clang for @available checks.
// Provide a weak fallback so older toolchains link; newer SDKs supply it.
__attribute__((weak))
int __isPlatformVersionAtLeast(uint32_t platform, uint32_t major, uint32_t minor, uint32_t build) {
    (void)platform; (void)major; (void)minor; (void)build;
    return 1;
}

static const uint16_t kLocalHttpPort = 8080;
static const uint16_t kLocalTcpPort = 19000;

// libcurl option constants (avoiding dependency on <curl/curl.h> in iOS SDK)
#define ROS_CURLOPT_SSL_VERIFYPEER 64
#define ROS_CURLOPT_SSL_VERIFYHOST 81
#define ROS_CURLOPT_URL 10002

@interface RosKenorRedirectProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *dataTask;
+ (BOOL)shouldRedirectHost:(NSString *)host;
+ (NSURL *)rewrittenURLForURL:(NSURL *)url;
+ (NSURLRequest *)rewrittenRequestForRequest:(NSURLRequest *)request;
@end

// Original function pointers resolved before fishhook rebinding
static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static int (*orig_curl_easy_setopt)(void *, int, ...) = NULL;
static CFHTTPMessageRef (*orig_CFHTTPMessageCreateRequest)(
    CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef) = NULL;

static BOOL ros_should_redirect_ipv4(in_addr_t s_addr) {
    return s_addr == inet_addr(kOldServerIP) ||
           s_addr == inet_addr(kAltGameIP) ||
           s_addr == inet_addr(kNeteaseEdgeIP);
}

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int (*real_connect)(int, const struct sockaddr *, socklen_t) = orig_connect;
    if (!real_connect) {
        real_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    }
    if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
        uint16_t port = ntohs(in_addr->sin_port);
        in_addr_t local_ip = inet_addr(kLocalGatewayIP);

        if (ros_should_redirect_ipv4(in_addr->sin_addr.s_addr) ||
            (in_addr->sin_addr.s_addr == local_ip &&
             (port == 443 || port == 80 || port == 19003 || port == 19009 || port == 20011))) {
            uint16_t mapped_port = port;
            if (port == 443) {
                mapped_port = kLocalHttpsPort;
            } else if (port == 80) {
                mapped_port = kLocalHttpPort;
            } else if (port == 19000 || port == 19003 || port == 19009 || port == 20011) {
                mapped_port = kLocalTcpPort;
            }
            struct sockaddr_in gw = *in_addr;
            gw.sin_addr.s_addr = local_ip;
            gw.sin_port = htons(mapped_port);
            char orig_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &in_addr->sin_addr, orig_ip, sizeof(orig_ip));
            NSLog(@"[RosKenorRedirect] connect %s:%u -> %s:%u",
                  orig_ip, port, kLocalGatewayIP, mapped_port);
            return real_connect(sockfd, (const struct sockaddr *)&gw, sizeof(gw));
        }
    }
    return real_connect(sockfd, addr, addrlen);
}

static int hooked_getaddrinfo(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res) {
    int (*real_gai)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = orig_getaddrinfo;
    if (!real_gai) {
        real_gai = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");
    }
    if (node != NULL) {
        @autoreleasepool {
            NSString *host = [NSString stringWithUTF8String:node];
            if ([RosKenorRedirectProtocol shouldRedirectHost:host]) {
                NSLog(@"[RosKenorRedirect] getaddrinfo %@ -> %s", host, kLocalGatewayIP);
                return real_gai(kLocalGatewayIP, service, hints, res);
            }
        }
    }
    return real_gai(node, service, hints, res);
}

static OSStatus hooked_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    (void)trust;
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}

static bool hooked_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    (void)trust;
    if (error) {
        *error = NULL;
    }
    return true;
}

static int hooked_curl_easy_setopt(void *curl, int option, ...) {
    int (*real_setopt)(void *, int, ...) = orig_curl_easy_setopt;
    if (!real_setopt) {
        real_setopt = (int (*)(void *, int, ...))dlsym(RTLD_NEXT, "curl_easy_setopt");
    }
    if (!real_setopt) {
        return 0;
    }

    va_list ap;
    va_start(ap, option);

    if (option == ROS_CURLOPT_URL) {
        const char *raw_url = va_arg(ap, const char *);
        va_end(ap);
        if (raw_url != NULL) {
            @autoreleasepool {
                NSString *urlStr = [NSString stringWithUTF8String:raw_url];
                NSURL *parsed = urlStr ? [NSURL URLWithString:urlStr] : nil;
                NSURL *rewritten = parsed ? [RosKenorRedirectProtocol rewrittenURLForURL:parsed] : nil;
                if (rewritten != nil) {
                    const char *new_cstr = rewritten.absoluteString.UTF8String;
                    int rc = real_setopt(curl, option, new_cstr);
                    real_setopt(curl, ROS_CURLOPT_SSL_VERIFYPEER, 0L);
                    real_setopt(curl, ROS_CURLOPT_SSL_VERIFYHOST, 0L);
                    return rc;
                }
            }
        }
        return real_setopt(curl, option, raw_url);
    }

    if (option == ROS_CURLOPT_SSL_VERIFYPEER || option == ROS_CURLOPT_SSL_VERIFYHOST) {
        (void)va_arg(ap, long);
        va_end(ap);
        return real_setopt(curl, option, 0L);
    }

    uintptr_t arg = va_arg(ap, uintptr_t);
    va_end(ap);
    return real_setopt(curl, option, arg);
}

static CFHTTPMessageRef hooked_CFHTTPMessageCreateRequest(
    CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef url, CFStringRef httpVersion) {
    CFURLRef targetURL = url;
    if (url != NULL) {
        @autoreleasepool {
            NSURL *nsURL = (__bridge NSURL *)url;
            NSURL *rewritten = [RosKenorRedirectProtocol rewrittenURLForURL:nsURL];
            if (rewritten != nil) {
                targetURL = (__bridge CFURLRef)rewritten;
                if (orig_CFHTTPMessageCreateRequest) {
                    return orig_CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
                }
                return CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
            }
        }
    }
    if (orig_CFHTTPMessageCreateRequest) {
        return orig_CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
    }
    return CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
}

@interface RosKenorAuthController : NSObject
+ (void)installLoginOverlayHooks;
@end

@implementation RosKenorRedirectProtocol

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Resolve real implementations BEFORE fishhook walks all images, so
        // unrelated framework lazy stub_helpers never overwrite our orig_* pointers.
        orig_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_DEFAULT, "connect");
        orig_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_DEFAULT, "getaddrinfo");
        orig_curl_easy_setopt = (int (*)(void *, int, ...))dlsym(RTLD_DEFAULT, "curl_easy_setopt");
        orig_CFHTTPMessageCreateRequest = (CFHTTPMessageRef (*)(CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFHTTPMessageCreateRequest");

        struct rebinding rebindings[] = {
            {"connect", (void *)hooked_connect, NULL},
            {"getaddrinfo", (void *)hooked_getaddrinfo, NULL},
            {"SecTrustEvaluate", (void *)hooked_SecTrustEvaluate, NULL},
            {"SecTrustEvaluateWithError", (void *)hooked_SecTrustEvaluateWithError, NULL},
            {"curl_easy_setopt", (void *)hooked_curl_easy_setopt, NULL},
            {"CFHTTPMessageCreateRequest", (void *)hooked_CFHTTPMessageCreateRequest, NULL},
        };
        rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        NSLog(@"[RosKenorRedirect] loaded and rebound connect/getaddrinfo/SecTrust/CFHTTPMessage (orig_connect=%p)", (void *)orig_connect);

        [NSURLProtocol registerClass:[RosKenorRedirectProtocol class]];
        [self swizzleSessionConfiguration];
        [self swizzleURLSessionTasks];
        [RosKenorAuthController installLoginOverlayHooks];
    });
}

+ (void)swizzleSessionConfiguration {
    Class cls = NSClassFromString(@"__NSCFURLSessionConfiguration") ?: [NSURLSessionConfiguration class];
    Method orig = class_getInstanceMethod(cls, @selector(protocolClasses));
    if (!orig) return;

    IMP origIMP = method_getImplementation(orig);
    IMP newIMP = imp_implementationWithBlock(^NSArray<Class> *(id selfObj) {
        NSArray<Class> *classes = ((NSArray<Class> *(*)(id, SEL))origIMP)(selfObj, @selector(protocolClasses));
        NSMutableArray<Class> *mut = classes ? [classes mutableCopy] : [NSMutableArray array];
        if (![mut containsObject:[RosKenorRedirectProtocol class]]) {
            [mut insertObject:[RosKenorRedirectProtocol class] atIndex:0];
        }
        return mut;
    });
    method_setImplementation(orig, newIMP);
}

+ (void)swizzleURLSessionTasks {
    Class cls = [NSURLSession class];

    Method reqMethod = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:));
    if (reqMethod) {
        IMP origReqIMP = method_getImplementation(reqMethod);
        IMP newReqIMP = imp_implementationWithBlock(^NSURLSessionDataTask *(id selfObj, NSURLRequest *req) {
            NSURLRequest *rewritten = [RosKenorRedirectProtocol rewrittenRequestForRequest:req];
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *))origReqIMP)(
                selfObj, @selector(dataTaskWithRequest:), rewritten ?: req);
        });
        method_setImplementation(reqMethod, newReqIMP);
    }

    Method urlMethod = class_getInstanceMethod(cls, @selector(dataTaskWithURL:));
    if (urlMethod) {
        IMP origURLIMP = method_getImplementation(urlMethod);
        IMP newURLIMP = imp_implementationWithBlock(^NSURLSessionDataTask *(id selfObj, NSURL *url) {
            NSURL *rewritten = [RosKenorRedirectProtocol rewrittenURLForURL:url];
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURL *))origURLIMP)(
                selfObj, @selector(dataTaskWithURL:), rewritten ?: url);
        });
        method_setImplementation(urlMethod, newURLIMP);
    }

    Method reqCompMethod = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
    if (reqCompMethod) {
        IMP origReqCompIMP = method_getImplementation(reqCompMethod);
        IMP newReqCompIMP = imp_implementationWithBlock(^NSURLSessionDataTask *(id selfObj, NSURLRequest *req, id handler) {
            NSURLRequest *rewritten = [RosKenorRedirectProtocol rewrittenRequestForRequest:req];
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))origReqCompIMP)(
                selfObj, @selector(dataTaskWithRequest:completionHandler:), rewritten ?: req, handler);
        });
        method_setImplementation(reqCompMethod, newReqCompIMP);
    }

    Method urlCompMethod = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
    if (urlCompMethod) {
        IMP origURLCompIMP = method_getImplementation(urlCompMethod);
        IMP newURLCompIMP = imp_implementationWithBlock(^NSURLSessionDataTask *(id selfObj, NSURL *url, id handler) {
            NSURL *rewritten = [RosKenorRedirectProtocol rewrittenURLForURL:url];
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURL *, id))origURLCompIMP)(
                selfObj, @selector(dataTaskWithURL:completionHandler:), rewritten ?: url, handler);
        });
        method_setImplementation(urlCompMethod, newURLCompIMP);
    }
}

+ (BOOL)shouldRedirectHost:(NSString *)host {
    if (!host || host.length == 0) return NO;
    NSString *lower = host.lowercaseString;
    if ([lower isEqualToString:@"api.stillchooseyou.site"]) {
        return NO;
    }
    NSSet<NSString *> *exact = [NSSet setWithObjects:
        @"172.65.54.209",
        @"172.104.170.200",
        @"223.252.216.48",
        @"api.roslegacy.net",
        @"cdn.mobile.roslegacy.net",
        @"mirae-labs.com",
        @"topup.mythgames.net",
        @"easebar.com",
        @"netease.com",
        @"163.com",
        nil];
    if ([exact containsObject:lower]) return YES;
    return [lower hasSuffix:@".roslegacy.net"] ||
           [lower hasSuffix:@".mirae-labs.com"] ||
           [lower hasSuffix:@".easebar.com"] ||
           [lower hasSuffix:@".netease.com"] ||
           [lower hasSuffix:@".163.com"];
}

+ (NSURL *)rewrittenURLForURL:(NSURL *)url {
    if (!url || ![self shouldRedirectHost:url.host]) {
        return nil;
    }
    NSURLComponents *comps = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSURLComponents *target = [NSURLComponents componentsWithString:kRosKenorBaseURL];
    if (!comps || !target) {
        return nil;
    }
    comps.scheme = target.scheme;
    comps.host = target.host;
    comps.port = target.port;
    return comps.URL;
}

+ (NSURLRequest *)rewrittenRequestForRequest:(NSURLRequest *)request {
    NSURL *rewritten = [self rewrittenURLForURL:request.URL];
    if (!rewritten) {
        return nil;
    }
    NSMutableURLRequest *mutableReq = [request mutableCopy];
    mutableReq.URL = rewritten;
    return mutableReq;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:kHandledKey inRequest:request]) {
        return NO;
    }
    return [self shouldRedirectHost:request.URL.host];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *mutableReq = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kHandledKey inRequest:mutableReq];

    NSURL *rewritten = [RosKenorRedirectProtocol rewrittenURLForURL:mutableReq.URL];
    if (rewritten) {
        mutableReq.URL = rewritten;
    }

    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:self
                                                     delegateQueue:nil];
    self.dataTask = [session dataTaskWithRequest:mutableReq];
    [self.dataTask resume];
}

- (void)stopLoading {
    [self.dataTask cancel];
    self.dataTask = nil;
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        challenge.protectionSpace.serverTrust != NULL) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
    } else {
        [self.client URLProtocolDidFinishLoading:self];
    }
}

@end


#pragma mark - Redesigned Native Ros Kenor Login & Persistent Device Session Overlay

static NSString *const kRKDefaultsDeviceId = @"rk_persistent_device_id";
static NSString *const kRKDefaultsSession = @"rk_saved_session_token";
static NSString *const kRKDefaultsUsername = @"rk_saved_username";
static NSString *const kRKDefaultsNickname = @"rk_saved_nickname";
static NSString *const kRKDefaultsUid = @"rk_saved_uid";

static const void *kRKOverlayAssocKey = &kRKOverlayAssocKey;

@interface RosKenorAuthView : UIView <UITextFieldDelegate, NSURLSessionDelegate>
@property (nonatomic, weak) UIViewController *hostVC;
@property (nonatomic, strong) NSURLSession *apiSession;
@property (nonatomic, strong) UIScrollView *scrollView;
@property (nonatomic, strong) UIView *cardContainer;
@property (nonatomic, strong) UIView *leftRail;
@property (nonatomic, strong) UIView *rightPane;
@property (nonatomic, strong) CAGradientLayer *bgGradient;
@property (nonatomic, strong) CAGradientLayer *ctaGradient;
@property (nonatomic, strong) CAGradientLayer *crestGradient;
@property (nonatomic, strong) UISegmentedControl *modeSegment;
@property (nonatomic, strong) UIView *resumeCard;
@property (nonatomic, strong) UILabel *resumeTitleLabel;
@property (nonatomic, strong) UILabel *resumeSubLabel;
@property (nonatomic, strong) UIActivityIndicatorView *resumeSpinner;
@property (nonatomic, strong) UIButton *resumeContinueBtn;
@property (nonatomic, strong) UIButton *resumeSwitchBtn;
@property (nonatomic, strong) UIView *formContainer;
@property (nonatomic, strong) UITextField *loginUserField;
@property (nonatomic, strong) UITextField *loginPassField;
@property (nonatomic, strong) UISwitch *rememberSwitch;
@property (nonatomic, strong) UIView *rememberRow;
@property (nonatomic, strong) UITextField *regUserField;
@property (nonatomic, strong) UITextField *regNickField;
@property (nonatomic, strong) UITextField *regPassField;
@property (nonatomic, strong) UITextField *regConfirmField;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *quickCreateBtn;
@property (nonatomic, strong) UIButton *primaryBtn;
@property (nonatomic, strong) UILabel *onlineLabel;
@property (nonatomic, strong) UILabel *sigStatusLabel;
@property (nonatomic, strong) UILabel *sigDetailLabel;
@property (nonatomic, assign) BOOL isRegisterMode;
@property (nonatomic, assign) BOOL isBusy;
@property (nonatomic, assign) BOOL autoDeployCancelled;
@property (nonatomic, assign) NSInteger appliedLayoutMode;
@property (nonatomic, strong) NSArray<NSLayoutConstraint *> *layoutModeConstraints;
@property (nonatomic, strong) UIButton *hiddenDeployBridge;
@property (nonatomic, strong) UILabel *hiddenErrBridge;
@property (nonatomic, strong) UIButton *hiddenLogoutBridge;
- (instancetype)initWithHostVC:(UIViewController *)vc frame:(CGRect)frame;
- (void)attemptAutoResumeOnLaunch;
@end

static NSString *rk_library_file_path(NSString *name) {
    NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    NSString *libDir = dirs.firstObject ?: NSTemporaryDirectory();
    return [libDir stringByAppendingPathComponent:name];
}

static NSString *rk_get_device_id(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *saved = [ud stringForKey:kRKDefaultsDeviceId];
    if (saved.length > 0) return saved;
    NSString *idfv = [[UIDevice currentDevice].identifierForVendor UUIDString];
    NSString *chosen = idfv.length > 0 ? idfv : [[NSUUID UUID] UUIDString];
    [ud setObject:chosen forKey:kRKDefaultsDeviceId];
    [ud synchronize];
    return chosen;
}

static NSString *rk_read_saved_session_token(void) {
    NSString *path = rk_library_file_path(@"ros_session");
    NSString *fileTok = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    fileTok = [fileTok stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (fileTok.length > 0) return fileTok;
    return [[NSUserDefaults standardUserDefaults] stringForKey:kRKDefaultsSession];
}

static void rk_persist_session(NSString *sessionToken, NSString *username, NSString *nickname, NSNumber *uid) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if (sessionToken.length > 0) {
        [sessionToken writeToFile:rk_library_file_path(@"ros_session") atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [ud setObject:sessionToken forKey:kRKDefaultsSession];
    }
    if (username.length > 0) {
        [username writeToFile:rk_library_file_path(@"ros_session_user") atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [ud setObject:username forKey:kRKDefaultsUsername];
    }
    if (nickname.length > 0) {
        [ud setObject:nickname forKey:kRKDefaultsNickname];
    }
    if (uid != nil) {
        [ud setObject:uid forKey:kRKDefaultsUid];
    }
    [ud synchronize];
}

static void rk_clear_saved_session(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:rk_library_file_path(@"ros_session") error:nil];
    [fm removeItemAtPath:rk_library_file_path(@"ros_session_user") error:nil];
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud removeObjectForKey:kRKDefaultsSession];
    [ud removeObjectForKey:kRKDefaultsUsername];
    [ud removeObjectForKey:kRKDefaultsNickname];
    [ud removeObjectForKey:kRKDefaultsUid];
    [ud synchronize];
}

static NSString *rk_read_provision_expiry(NSString **detailOut) {
    NSString *provPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    if (!provPath) {
        if (detailOut) *detailOut = @"Signed locally via Sideload / PC Installer";
        return @"ACTIVE";
    }
    NSData *data = [NSData dataWithContentsOfFile:provPath];
    if (!data) {
        if (detailOut) *detailOut = @"Provisioning profile loaded";
        return @"ACTIVE";
    }
    NSString *raw = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    NSRange start = [raw rangeOfString:@"<?xml"];
    NSRange end = [raw rangeOfString:@"</plist>"];
    if (start.location != NSNotFound && end.location != NSNotFound && end.location > start.location) {
        NSString *xmlStr = [raw substringWithRange:NSMakeRange(start.location, NSMaxRange(end) - start.location)];
        NSData *xmlData = [xmlStr dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:xmlData options:NSPropertyListImmutable format:nil error:nil];
        NSDate *exp = plist[@"ExpirationDate"];
        if ([exp isKindOfClass:[NSDate class]]) {
            NSTimeInterval rem = [exp timeIntervalSinceNow];
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
            df.dateFormat = @"EEE d MMM HH:mm";
            if (detailOut) {
                *detailOut = [NSString stringWithFormat:@"Expires %@ • Renew via PC installer", [df stringFromDate:exp]];
            }
            if (rem <= 0) return @"EXPIRED";
            long days = (long)(rem / 86400.0);
            if (days >= 1) return [NSString stringWithFormat:@"%ld DAYS LEFT", days];
            long hrs = MAX(1, (long)(rem / 3600.0));
            return [NSString stringWithFormat:@"%ld HOURS LEFT", hrs];
        }
    }
    if (detailOut) *detailOut = @"Signed for iOS device";
    return @"ACTIVE";
}

@implementation RosKenorAuthView

- (UIColor *)cBgCard { return [UIColor colorWithRed:9/255.0 green:17/255.0 blue:32/255.0 alpha:0.86]; }
- (UIColor *)cBgRail { return [UIColor colorWithRed:12/255.0 green:23/255.0 blue:44/255.0 alpha:0.90]; }
- (UIColor *)cField { return [UIColor colorWithRed:6/255.0 green:12/255.0 blue:24/255.0 alpha:0.95]; }
- (UIColor *)cAccent { return [UIColor colorWithRed:56/255.0 green:189/255.0 blue:248/255.0 alpha:1.0]; }

- (UITextField *)makeFieldWithPlaceholder:(NSString *)ph secure:(BOOL)secure tag:(NSInteger)tag {
    UITextField *tf = [[UITextField alloc] init];
    tf.translatesAutoresizingMaskIntoConstraints = NO;
    tf.backgroundColor = [self cField];
    tf.textColor = [UIColor whiteColor];
    tf.tintColor = [self cAccent];
    tf.font = [UIFont systemFontOfSize:14.5 weight:UIFontWeightMedium];
    tf.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:ph
            attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:1.0 alpha:0.38]}];
    tf.layer.cornerRadius = 10.0;
    tf.layer.borderWidth = 1.0;
    tf.layer.borderColor = [UIColor colorWithRed:100/255.0 green:116/255.0 blue:139/255.0 alpha:0.42].CGColor;
    tf.secureTextEntry = secure;
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    tf.returnKeyType = UIReturnKeyNext;
    tf.delegate = self;
    tf.tag = tag;
    UIView *pad = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 12, 10)];
    tf.leftView = pad;
    tf.leftViewMode = UITextFieldViewModeAlways;
    [tf.heightAnchor constraintEqualToConstant:40.0].active = YES;
    return tf;
}

- (UIView *)labeledField:(NSString *)caption field:(UITextField *)tf {
    UIStackView *sv = [[UIStackView alloc] init];
    sv.axis = UILayoutConstraintAxisVertical;
    sv.spacing = 4.0;
    sv.translatesAutoresizingMaskIntoConstraints = NO;
    UILabel *lbl = [[UILabel alloc] init];
    lbl.text = caption;
    lbl.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightBold];
    lbl.textColor = [UIColor colorWithRed:159/255.0 green:179/255.0 blue:200/255.0 alpha:1.0];
    [sv addArrangedSubview:lbl];
    [sv addArrangedSubview:tf];
    return sv;
}

- (instancetype)initWithHostVC:(UIViewController *)vc frame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    _hostVC = vc;
    self.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;

    _bgGradient = [CAGradientLayer layer];
    _bgGradient.colors = @[
        (id)[UIColor colorWithRed:11/255.0 green:23/255.0 blue:44/255.0 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:5/255.0 green:10/255.0 blue:20/255.0 alpha:1.0].CGColor,
    ];
    _bgGradient.startPoint = CGPointMake(0.15, 0.0);
    _bgGradient.endPoint = CGPointMake(0.85, 1.0);
    [self.layer insertSublayer:_bgGradient atIndex:0];

    NSData *bgData = [NSData dataWithBytesNoCopy:(void *)kRKPlayBgJpg length:kRKPlayBgJpg_len freeWhenDone:NO];
    UIImage *bgImg = [UIImage imageWithData:bgData];
    if (bgImg) {
        UIImageView *bgView = [[UIImageView alloc] initWithImage:bgImg];
        bgView.contentMode = UIViewContentModeScaleAspectFill;
        bgView.clipsToBounds = YES;
        bgView.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:bgView];
        [NSLayoutConstraint activateConstraints:@[
            [bgView.topAnchor constraintEqualToAnchor:self.topAnchor],
            [bgView.bottomAnchor constraintEqualToAnchor:self.bottomAnchor],
            [bgView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
            [bgView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
        ]];
        UIView *scrim = [[UIView alloc] init];
        scrim.backgroundColor = [UIColor colorWithRed:5/255.0 green:10/255.0 blue:20/255.0 alpha:0.46];
        scrim.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:scrim];
        [NSLayoutConstraint activateConstraints:@[
            [scrim.topAnchor constraintEqualToAnchor:self.topAnchor],
            [scrim.bottomAnchor constraintEqualToAnchor:self.bottomAnchor],
            [scrim.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
            [scrim.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
        ]];
    }

    // Off-screen compatibility bridges passed into RosLoginVC's native doDeploy:button:logout:
    _hiddenErrBridge = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
    _hiddenErrBridge.hidden = YES;
    [self addSubview:_hiddenErrBridge];

    Class rosBtnCls = NSClassFromString(@"RosButton");
    if (rosBtnCls && [rosBtnCls respondsToSelector:@selector(primary:icon:)]) {
        id (*msgFn)(id, SEL, id, id) = (id (*)(id, SEL, id, id))objc_msgSend;
        _hiddenDeployBridge = msgFn(rosBtnCls, @selector(primary:icon:), @"DEPLOY", nil);
    } else {
        _hiddenDeployBridge = [UIButton buttonWithType:UIButtonTypeSystem];
    }
    _hiddenDeployBridge.hidden = YES;
    [self addSubview:_hiddenDeployBridge];

    _hiddenLogoutBridge = [UIButton buttonWithType:UIButtonTypeSystem];
    _hiddenLogoutBridge.hidden = YES;
    [self addSubview:_hiddenLogoutBridge];

    _scrollView = [[UIScrollView alloc] init];
    _scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    _scrollView.alwaysBounceVertical = NO;
    _scrollView.showsVerticalScrollIndicator = NO;
    [self addSubview:_scrollView];

    [NSLayoutConstraint activateConstraints:@[
        [_scrollView.topAnchor constraintEqualToAnchor:self.topAnchor],
        [_scrollView.bottomAnchor constraintEqualToAnchor:self.bottomAnchor],
        [_scrollView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
        [_scrollView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
    ]];

    UITapGestureRecognizer *dismissTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(endEditingForce)];
    dismissTap.cancelsTouchesInView = NO;
    [_scrollView addGestureRecognizer:dismissTap];

    _cardContainer = [[UIView alloc] init];
    _cardContainer.translatesAutoresizingMaskIntoConstraints = NO;
    _cardContainer.backgroundColor = [self cBgCard];
    _cardContainer.layer.cornerRadius = 20.0;
    _cardContainer.layer.borderWidth = 1.0;
    _cardContainer.layer.borderColor = [UIColor colorWithRed:56/255.0 green:189/255.0 blue:248/255.0 alpha:0.28].CGColor;
    _cardContainer.layer.masksToBounds = YES;
    [_scrollView addSubview:_cardContainer];

    [NSLayoutConstraint activateConstraints:@[
        [_cardContainer.centerXAnchor constraintEqualToAnchor:_scrollView.frameLayoutGuide.centerXAnchor],
        [_cardContainer.centerYAnchor constraintEqualToAnchor:_scrollView.frameLayoutGuide.centerYAnchor],
        [_cardContainer.widthAnchor constraintLessThanOrEqualToConstant:780.0],
        [_cardContainer.widthAnchor constraintLessThanOrEqualToAnchor:_scrollView.frameLayoutGuide.widthAnchor constant:-32.0],
        [_cardContainer.heightAnchor constraintLessThanOrEqualToAnchor:_scrollView.frameLayoutGuide.heightAnchor constant:-24.0],
    ]];

    [self buildLeftRail];
    [self buildRightPane];
    [self applyResponsiveOrientationConstraints];
    [self fetchOnlineCount];

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onKeyboardChange:) name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onKeyboardHide:) name:UIKeyboardWillHideNotification object:nil];

    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_apiSession invalidateAndCancel];
    _apiSession = nil;
}

- (void)endEditingForce {
    [self endEditing:YES];
}

- (void)buildLeftRail {
    _leftRail = [[UIView alloc] init];
    _leftRail.translatesAutoresizingMaskIntoConstraints = NO;
    _leftRail.backgroundColor = [self cBgRail];
    [_cardContainer addSubview:_leftRail];

    NSData *logoData = [NSData dataWithBytesNoCopy:(void *)kRKLogoPng length:kRKLogoPng_len freeWhenDone:NO];
    UIImage *logoImg = [UIImage imageWithData:logoData];
    UIImageView *crest = [[UIImageView alloc] initWithImage:logoImg];
    crest.translatesAutoresizingMaskIntoConstraints = NO;
    crest.contentMode = UIViewContentModeScaleAspectFit;
    [NSLayoutConstraint activateConstraints:@[
        [crest.widthAnchor constraintEqualToConstant:64],
        [crest.heightAnchor constraintEqualToConstant:64],
    ]];

    UILabel *kicker = [[UILabel alloc] init];
    kicker.text = @"PRIVATE SERVER";
    kicker.font = [UIFont systemFontOfSize:10 weight:UIFontWeightBold];
    kicker.textColor = [self cAccent];

    UILabel *brand = [[UILabel alloc] init];
    brand.text = @"ROS KENOR";
    brand.font = [UIFont systemFontOfSize:21 weight:UIFontWeightHeavy];
    brand.textColor = [UIColor whiteColor];

    UIStackView *brandText = [[UIStackView alloc] initWithArrangedSubviews:@[kicker, brand]];
    brandText.axis = UILayoutConstraintAxisVertical;
    brandText.spacing = 1;

    UIStackView *brandRow = [[UIStackView alloc] initWithArrangedSubviews:@[crest, brandText]];
    brandRow.axis = UILayoutConstraintAxisHorizontal;
    brandRow.alignment = UIStackViewAlignmentCenter;
    brandRow.spacing = 12;

    UILabel *desc = [[UILabel alloc] init];
    desc.text = @"Create an account before signing in. Your device session stays saved so reopening enters the lobby directly.";
    desc.numberOfLines = 0;
    desc.font = [UIFont systemFontOfSize:12.5 weight:UIFontWeightRegular];
    desc.textColor = [UIColor colorWithRed:148/255.0 green:163/255.0 blue:184/255.0 alpha:1.0];

    UIView *onlinePill = [[UIView alloc] init];
    onlinePill.backgroundColor = [UIColor colorWithRed:15/255.0 green:23/255.0 blue:42/255.0 alpha:0.85];
    onlinePill.layer.cornerRadius = 10;
    onlinePill.layer.borderWidth = 1;
    onlinePill.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.12].CGColor;
    _onlineLabel = [[UILabel alloc] init];
    _onlineLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _onlineLabel.text = @"● ASIA GATEWAY • ONLINE";
    _onlineLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightBold];
    _onlineLabel.textColor = [UIColor colorWithRed:52/255.0 green:211/255.0 blue:153/255.0 alpha:1.0];
    [onlinePill addSubview:_onlineLabel];
    [NSLayoutConstraint activateConstraints:@[
        [_onlineLabel.topAnchor constraintEqualToAnchor:onlinePill.topAnchor constant:8],
        [_onlineLabel.bottomAnchor constraintEqualToAnchor:onlinePill.bottomAnchor constant:-8],
        [_onlineLabel.leadingAnchor constraintEqualToAnchor:onlinePill.leadingAnchor constant:12],
        [_onlineLabel.trailingAnchor constraintEqualToAnchor:onlinePill.trailingAnchor constant:-12],
    ]];

    NSString *sigDetail = nil;
    NSString *sigBadge = rk_read_provision_expiry(&sigDetail);
    UIView *sigPill = [[UIView alloc] init];
    sigPill.backgroundColor = [UIColor colorWithRed:15/255.0 green:23/255.0 blue:42/255.0 alpha:0.85];
    sigPill.layer.cornerRadius = 10;
    sigPill.layer.borderWidth = 1;
    sigPill.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.12].CGColor;
    _sigStatusLabel = [[UILabel alloc] init];
    _sigStatusLabel.text = [NSString stringWithFormat:@"APP SIGNATURE • %@", sigBadge];
    _sigStatusLabel.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightBold];
    _sigStatusLabel.textColor = [sigBadge isEqualToString:@"EXPIRED"]
        ? [UIColor colorWithRed:248/255.0 green:113/255.0 blue:113/255.0 alpha:1.0]
        : [UIColor colorWithRed:56/255.0 green:189/255.0 blue:248/255.0 alpha:1.0];
    _sigDetailLabel = [[UILabel alloc] init];
    _sigDetailLabel.text = sigDetail ?: @"";
    _sigDetailLabel.numberOfLines = 2;
    _sigDetailLabel.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightRegular];
    _sigDetailLabel.textColor = [UIColor colorWithRed:148/255.0 green:163/255.0 blue:184/255.0 alpha:1.0];
    UIStackView *sigStack = [[UIStackView alloc] initWithArrangedSubviews:@[_sigStatusLabel, _sigDetailLabel]];
    sigStack.axis = UILayoutConstraintAxisVertical;
    sigStack.spacing = 2;
    sigStack.translatesAutoresizingMaskIntoConstraints = NO;
    [sigPill addSubview:sigStack];
    [NSLayoutConstraint activateConstraints:@[
        [sigStack.topAnchor constraintEqualToAnchor:sigPill.topAnchor constant:8],
        [sigStack.bottomAnchor constraintEqualToAnchor:sigPill.bottomAnchor constant:-8],
        [sigStack.leadingAnchor constraintEqualToAnchor:sigPill.leadingAnchor constant:12],
        [sigStack.trailingAnchor constraintEqualToAnchor:sigPill.trailingAnchor constant:-12],
    ]];

    UIStackView *railStack = [[UIStackView alloc] initWithArrangedSubviews:@[brandRow, desc, onlinePill, sigPill]];
    railStack.axis = UILayoutConstraintAxisVertical;
    railStack.spacing = 12;
    railStack.translatesAutoresizingMaskIntoConstraints = NO;
    [_leftRail addSubview:railStack];
    [NSLayoutConstraint activateConstraints:@[
        [railStack.topAnchor constraintEqualToAnchor:_leftRail.topAnchor constant:20],
        [railStack.bottomAnchor constraintEqualToAnchor:_leftRail.bottomAnchor constant:-20],
        [railStack.leadingAnchor constraintEqualToAnchor:_leftRail.leadingAnchor constant:20],
        [railStack.trailingAnchor constraintEqualToAnchor:_leftRail.trailingAnchor constant:-20],
    ]];
}

- (void)buildRightPane {
    _rightPane = [[UIView alloc] init];
    _rightPane.translatesAutoresizingMaskIntoConstraints = NO;
    [_cardContainer addSubview:_rightPane];

    // Resume / Auto-login card (shown when a saved session or device binding exists)
    _resumeCard = [[UIView alloc] init];
    _resumeCard.backgroundColor = [UIColor colorWithRed:14/255.0 green:165/255.0 blue:233/255.0 alpha:0.13];
    _resumeCard.layer.cornerRadius = 12;
    _resumeCard.layer.borderWidth = 1;
    _resumeCard.layer.borderColor = [UIColor colorWithRed:56/255.0 green:189/255.0 blue:248/255.0 alpha:0.42].CGColor;
    _resumeCard.hidden = YES;

    _resumeTitleLabel = [[UILabel alloc] init];
    _resumeTitleLabel.text = @"Restoring Saved Session...";
    _resumeTitleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    _resumeTitleLabel.textColor = [UIColor whiteColor];

    _resumeSubLabel = [[UILabel alloc] init];
    _resumeSubLabel.text = @"Checking device authorization";
    _resumeSubLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    _resumeSubLabel.textColor = [UIColor colorWithRed:186/255.0 green:230/255.0 blue:253/255.0 alpha:1.0];

    _resumeSpinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhite];
    [_resumeSpinner startAnimating];

    UIStackView *resumeTextStack = [[UIStackView alloc] initWithArrangedSubviews:@[_resumeTitleLabel, _resumeSubLabel]];
    resumeTextStack.axis = UILayoutConstraintAxisVertical;
    resumeTextStack.spacing = 2;

    UIStackView *resumeTop = [[UIStackView alloc] initWithArrangedSubviews:@[resumeTextStack, _resumeSpinner]];
    resumeTop.axis = UILayoutConstraintAxisHorizontal;
    resumeTop.alignment = UIStackViewAlignmentCenter;
    resumeTop.spacing = 8;

    _resumeContinueBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_resumeContinueBtn setTitle:@"Enter Lobby" forState:UIControlStateNormal];
    [_resumeContinueBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _resumeContinueBtn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
    _resumeContinueBtn.backgroundColor = [UIColor colorWithRed:14/255.0 green:165/255.0 blue:233/255.0 alpha:0.95];
    _resumeContinueBtn.layer.cornerRadius = 8;
    _resumeContinueBtn.hidden = YES;

    _resumeSwitchBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_resumeSwitchBtn setTitle:@"Switch Account" forState:UIControlStateNormal];
    [_resumeSwitchBtn setTitleColor:[UIColor colorWithRed:203/255.0 green:213/255.0 blue:225/255.0 alpha:1.0] forState:UIControlStateNormal];
    _resumeSwitchBtn.titleLabel.font = [UIFont systemFontOfSize:12.5 weight:UIFontWeightSemibold];
    _resumeSwitchBtn.backgroundColor = [UIColor colorWithRed:30/255.0 green:41/255.0 blue:59/255.0 alpha:0.9];
    _resumeSwitchBtn.layer.cornerRadius = 8;
    [_resumeSwitchBtn addTarget:self action:@selector(onSwitchAccountTapped) forControlEvents:UIControlEventTouchUpInside];

    UIStackView *resumeBtnRow = [[UIStackView alloc] initWithArrangedSubviews:@[_resumeContinueBtn, _resumeSwitchBtn]];
    resumeBtnRow.axis = UILayoutConstraintAxisHorizontal;
    resumeBtnRow.spacing = 8;
    resumeBtnRow.distribution = UIStackViewDistributionFillEqually;
    [_resumeContinueBtn.heightAnchor constraintEqualToConstant:34].active = YES;
    [_resumeSwitchBtn.heightAnchor constraintEqualToConstant:34].active = YES;

    UIStackView *resumeStack = [[UIStackView alloc] initWithArrangedSubviews:@[resumeTop, resumeBtnRow]];
    resumeStack.axis = UILayoutConstraintAxisVertical;
    resumeStack.spacing = 8;
    resumeStack.translatesAutoresizingMaskIntoConstraints = NO;
    [_resumeCard addSubview:resumeStack];
    [NSLayoutConstraint activateConstraints:@[
        [resumeStack.topAnchor constraintEqualToAnchor:_resumeCard.topAnchor constant:12],
        [resumeStack.bottomAnchor constraintEqualToAnchor:_resumeCard.bottomAnchor constant:-12],
        [resumeStack.leadingAnchor constraintEqualToAnchor:_resumeCard.leadingAnchor constant:12],
        [resumeStack.trailingAnchor constraintEqualToAnchor:_resumeCard.trailingAnchor constant:-12],
    ]];

    _modeSegment = [[UISegmentedControl alloc] initWithItems:@[@"SIGN IN", @"CREATE ACCOUNT"]];
    _modeSegment.selectedSegmentIndex = 0;
    _modeSegment.backgroundColor = [UIColor colorWithRed:7/255.0 green:13/255.0 blue:25/255.0 alpha:1.0];
    if ([_modeSegment respondsToSelector:@selector(setSelectedSegmentTintColor:)]) {
        UIColor *segTint = [UIColor colorWithRed:14/255.0 green:165/255.0 blue:233/255.0 alpha:1.0];
        ((void (*)(id, SEL, id))objc_msgSend)(_modeSegment, @selector(setSelectedSegmentTintColor:), segTint);
    }
    [_modeSegment setTitleTextAttributes:@{
        NSForegroundColorAttributeName: [UIColor colorWithWhite:1.0 alpha:0.68],
        NSFontAttributeName: [UIFont systemFontOfSize:12 weight:UIFontWeightBold]
    } forState:UIControlStateNormal];
    [_modeSegment setTitleTextAttributes:@{
        NSForegroundColorAttributeName: [UIColor whiteColor],
        NSFontAttributeName: [UIFont systemFontOfSize:12 weight:UIFontWeightBold]
    } forState:UIControlStateSelected];
    [_modeSegment addTarget:self action:@selector(onModeChanged:) forControlEvents:UIControlEventValueChanged];
    [_modeSegment.heightAnchor constraintEqualToConstant:34].active = YES;

    _loginUserField = [self makeFieldWithPlaceholder:@"Created username or email" secure:NO tag:1];
    _loginPassField = [self makeFieldWithPlaceholder:@"Password" secure:YES tag:2];
    _loginPassField.returnKeyType = UIReturnKeyGo;

    _rememberSwitch = [[UISwitch alloc] init];
    _rememberSwitch.on = YES;
    _rememberSwitch.onTintColor = [UIColor colorWithRed:14/255.0 green:165/255.0 blue:233/255.0 alpha:1.0];
    _rememberSwitch.transform = CGAffineTransformMake(0.82, 0, 0, 0.82, 0, 0);
    UILabel *remLbl = [[UILabel alloc] init];
    remLbl.text = @"Remember this device (auto-login on reopen)";
    remLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    remLbl.textColor = [UIColor colorWithRed:203/255.0 green:213/255.0 blue:225/255.0 alpha:1.0];
    UIStackView *remStack = [[UIStackView alloc] initWithArrangedSubviews:@[_rememberSwitch, remLbl]];
    remStack.axis = UILayoutConstraintAxisHorizontal;
    remStack.alignment = UIStackViewAlignmentCenter;
    remStack.spacing = 6;
    _rememberRow = remStack;

    _regUserField = [self makeFieldWithPlaceholder:@"Username (3-24 chars)" secure:NO tag:10];
    _regNickField = [self makeFieldWithPlaceholder:@"In-game nickname (optional)" secure:NO tag:11];
    _regPassField = [self makeFieldWithPlaceholder:@"Password (6+ chars)" secure:YES tag:12];
    _regConfirmField = [self makeFieldWithPlaceholder:@"Confirm password" secure:YES tag:13];
    _regConfirmField.returnKeyType = UIReturnKeyGo;

    UIView *loginUserBlock = [self labeledField:@"USERNAME / EMAIL" field:_loginUserField];
    UIView *loginPassBlock = [self labeledField:@"PASSWORD" field:_loginPassField];
    UIView *regUserBlock = [self labeledField:@"NEW USERNAME" field:_regUserField];
    UIView *regNickBlock = [self labeledField:@"LOBBY NICKNAME" field:_regNickField];
    UIView *regPassBlock = [self labeledField:@"PASSWORD" field:_regPassField];
    UIView *regConfBlock = [self labeledField:@"CONFIRM PASSWORD" field:_regConfirmField];

    UIStackView *regNameRow = [[UIStackView alloc] initWithArrangedSubviews:@[regUserBlock, regNickBlock]];
    regNameRow.axis = UILayoutConstraintAxisHorizontal;
    regNameRow.spacing = 10;
    regNameRow.distribution = UIStackViewDistributionFillEqually;

    UIStackView *regPassRow = [[UIStackView alloc] initWithArrangedSubviews:@[regPassBlock, regConfBlock]];
    regPassRow.axis = UILayoutConstraintAxisHorizontal;
    regPassRow.spacing = 10;
    regPassRow.distribution = UIStackViewDistributionFillEqually;

    _statusLabel = [[UILabel alloc] init];
    _statusLabel.numberOfLines = 0;
    _statusLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    _statusLabel.hidden = YES;

    _quickCreateBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_quickCreateBtn setTitle:@"Account needed -> Switch to Create Account" forState:UIControlStateNormal];
    [_quickCreateBtn setTitleColor:[self cAccent] forState:UIControlStateNormal];
    _quickCreateBtn.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
    _quickCreateBtn.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    _quickCreateBtn.hidden = YES;
    [_quickCreateBtn addTarget:self action:@selector(onQuickCreateTapped) forControlEvents:UIControlEventTouchUpInside];

    _primaryBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    [_primaryBtn setTitle:@"SIGN IN" forState:UIControlStateNormal];
    [_primaryBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _primaryBtn.titleLabel.font = [UIFont systemFontOfSize:14.5 weight:UIFontWeightBold];
    _primaryBtn.layer.cornerRadius = 11;
    _primaryBtn.layer.masksToBounds = YES;
    [_primaryBtn.heightAnchor constraintEqualToConstant:42].active = YES;
    _ctaGradient = [CAGradientLayer layer];
    _ctaGradient.colors = @[
        (id)[UIColor colorWithRed:14/255.0 green:165/255.0 blue:233/255.0 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:37/255.0 green:99/255.0 blue:235/255.0 alpha:1.0].CGColor,
    ];
    _ctaGradient.startPoint = CGPointMake(0, 0.5);
    _ctaGradient.endPoint = CGPointMake(1, 0.5);
    [_primaryBtn.layer insertSublayer:_ctaGradient atIndex:0];
    [_primaryBtn addTarget:self action:@selector(onPrimaryTapped) forControlEvents:UIControlEventTouchUpInside];

    // Tag rows to toggle visibility cleanly between Sign In (tag 101) and Register (tag 102)
    loginUserBlock.tag = 101;
    loginPassBlock.tag = 101;
    _rememberRow.tag = 101;
    regNameRow.tag = 102;
    regPassRow.tag = 102;
    regNameRow.hidden = YES;
    regPassRow.hidden = YES;

    UIStackView *rightStack = [[UIStackView alloc] initWithArrangedSubviews:@[
        _resumeCard,
        _modeSegment,
        loginUserBlock,
        loginPassBlock,
        _rememberRow,
        regNameRow,
        regPassRow,
        _statusLabel,
        _quickCreateBtn,
        _primaryBtn
    ]];
    rightStack.axis = UILayoutConstraintAxisVertical;
    rightStack.spacing = 10;
    rightStack.translatesAutoresizingMaskIntoConstraints = NO;
    _formContainer = rightStack;
    [_rightPane addSubview:rightStack];

    [NSLayoutConstraint activateConstraints:@[
        [rightStack.topAnchor constraintEqualToAnchor:_rightPane.topAnchor constant:20],
        [rightStack.bottomAnchor constraintEqualToAnchor:_rightPane.bottomAnchor constant:-20],
        [rightStack.leadingAnchor constraintEqualToAnchor:_rightPane.leadingAnchor constant:22],
        [rightStack.trailingAnchor constraintEqualToAnchor:_rightPane.trailingAnchor constant:-22],
    ]];
}

- (void)applyResponsiveOrientationConstraints {
    BOOL wide = self.bounds.size.width >= 620.0;
    NSInteger targetMode = wide ? 2 : 1;
    if (_appliedLayoutMode == targetMode && _layoutModeConstraints.count > 0) {
        return;
    }
    _appliedLayoutMode = targetMode;
    if (_layoutModeConstraints.count > 0) {
        [NSLayoutConstraint deactivateConstraints:_layoutModeConstraints];
    }
    if (wide) {
        _layoutModeConstraints = @[
            [_leftRail.topAnchor constraintEqualToAnchor:_cardContainer.topAnchor],
            [_leftRail.bottomAnchor constraintEqualToAnchor:_cardContainer.bottomAnchor],
            [_leftRail.leadingAnchor constraintEqualToAnchor:_cardContainer.leadingAnchor],
            [_leftRail.widthAnchor constraintEqualToConstant:268.0],
            [_rightPane.topAnchor constraintEqualToAnchor:_cardContainer.topAnchor],
            [_rightPane.bottomAnchor constraintEqualToAnchor:_cardContainer.bottomAnchor],
            [_rightPane.leadingAnchor constraintEqualToAnchor:_leftRail.trailingAnchor],
            [_rightPane.trailingAnchor constraintEqualToAnchor:_cardContainer.trailingAnchor],
        ];
    } else {
        _layoutModeConstraints = @[
            [_leftRail.topAnchor constraintEqualToAnchor:_cardContainer.topAnchor],
            [_leftRail.leadingAnchor constraintEqualToAnchor:_cardContainer.leadingAnchor],
            [_leftRail.trailingAnchor constraintEqualToAnchor:_cardContainer.trailingAnchor],
            [_rightPane.topAnchor constraintEqualToAnchor:_leftRail.bottomAnchor],
            [_rightPane.bottomAnchor constraintEqualToAnchor:_cardContainer.bottomAnchor],
            [_rightPane.leadingAnchor constraintEqualToAnchor:_cardContainer.leadingAnchor],
            [_rightPane.trailingAnchor constraintEqualToAnchor:_cardContainer.trailingAnchor],
        ];
    }
    [NSLayoutConstraint activateConstraints:_layoutModeConstraints];
}

- (void)layoutSubviews {
    [super layoutSubviews];
    _bgGradient.frame = self.bounds;
    _ctaGradient.frame = _primaryBtn.bounds;
    [self applyResponsiveOrientationConstraints];
}

- (void)onModeChanged:(UISegmentedControl *)seg {
    _isRegisterMode = (seg.selectedSegmentIndex == 1);
    for (UIView *sub in ((UIStackView *)_formContainer).arrangedSubviews) {
        if (sub.tag == 101) sub.hidden = _isRegisterMode;
        if (sub.tag == 102) sub.hidden = !_isRegisterMode;
    }
    _statusLabel.hidden = YES;
    _quickCreateBtn.hidden = YES;
    [_primaryBtn setTitle:(_isRegisterMode ? @"CREATE ACCOUNT & ENTER" : @"SIGN IN") forState:UIControlStateNormal];
}

- (void)onQuickCreateTapped {
    _regUserField.text = _loginUserField.text;
    _modeSegment.selectedSegmentIndex = 1;
    [self onModeChanged:_modeSegment];
}

- (void)showStatus:(NSString *)msg isError:(BOOL)isErr showCreateShortcut:(BOOL)showShortcut {
    _statusLabel.text = msg;
    _statusLabel.textColor = isErr
        ? [UIColor colorWithRed:248/255.0 green:113/255.0 blue:113/255.0 alpha:1.0]
        : [UIColor colorWithRed:52/255.0 green:211/255.0 blue:153/255.0 alpha:1.0];
    _statusLabel.hidden = NO;
    _quickCreateBtn.hidden = !showShortcut;
}

- (void)setBusyState:(BOOL)busy buttonTitle:(NSString *)title {
    _isBusy = busy;
    _primaryBtn.enabled = !busy;
    _primaryBtn.alpha = busy ? 0.65 : 1.0;
    if (title) {
        [_primaryBtn setTitle:title forState:UIControlStateNormal];
    }
}

- (NSURLSession *)ensureApiSession {
    if (!_apiSession) {
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = 10.0;
        _apiSession = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    }
    return _apiSession;
}

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        challenge.protectionSpace.serverTrust != NULL) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

- (void)fetchOnlineCount {
    NSURL *origURL = [NSURL URLWithString:@"https://api.roslegacy.net/v2/ros/online-count"];
    NSURL *targetURL = [RosKenorRedirectProtocol rewrittenURLForURL:origURL] ?: origURL;
    [[[self ensureApiSession] dataTaskWithURL:targetURL completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (!data || err) return;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSNumber *cnt = [json isKindOfClass:[NSDictionary class]] ? (json[@"total_online"] ?: json[@"online"]) : nil;
        if (cnt) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.onlineLabel.text = [NSString stringWithFormat:@"● ASIA GATEWAY • %@ ONLINE", cnt];
            });
        }
    }] resume];
}

- (void)postJSONPath:(NSString *)urlStr body:(NSDictionary *)body completion:(void (^)(NSDictionary *json, NSInteger status, NSError *err))done {
    NSURL *origURL = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:origURL];
    NSURLRequest *rewritten = [RosKenorRedirectProtocol rewrittenRequestForRequest:req];
    NSMutableURLRequest *finalReq = rewritten ? [rewritten mutableCopy] : req;
    finalReq.HTTPMethod = @"POST";
    finalReq.timeoutInterval = 10.0;
    [finalReq setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [finalReq setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [finalReq setValue:rk_get_device_id() forHTTPHeaderField:@"X-Device-Id"];
    finalReq.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    [[[self ensureApiSession] dataTaskWithRequest:finalReq completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
        NSDictionary *parsed = nil;
        if (data.length > 0) {
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([obj isKindOfClass:[NSDictionary class]]) parsed = obj;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            done(parsed, code, err);
        });
    }] resume];
}

- (void)deployTicketToGame:(NSString *)ticket sessionToken:(NSString *)sessionToken username:(NSString *)username nickname:(NSString *)nickname uid:(NSNumber *)uid {
    rk_persist_session(sessionToken, username, nickname, uid);
    UIViewController *vc = self.hostVC;
    if (!vc || ticket.length == 0) return;
    @try {
        [vc setValue:ticket forKey:@"heldTicket"];
        [vc setValue:@([[NSDate date] timeIntervalSince1970]) forKey:@"heldAt"];
    } @catch (__unused NSException *ex) {}

    SEL deploySel = NSSelectorFromString(@"doDeploy:button:logout:");
    if ([vc respondsToSelector:deploySel]) {
        void (*fn)(id, SEL, id, id, id) = (void (*)(id, SEL, id, id, id))objc_msgSend;
        fn(vc, deploySel, _hiddenErrBridge, _hiddenDeployBridge, _hiddenLogoutBridge);
        return;
    }
    NSURL *deep = [NSURL URLWithString:[NSString stringWithFormat:@"rosmobile://?ticket=%@",
        [ticket stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]]]];
    if (deep) {
        [[UIApplication sharedApplication] openURL:deep options:@{} completionHandler:nil];
    }
}

- (void)attemptAutoResumeOnLaunch {
    NSString *savedSession = rk_read_saved_session_token();
    NSString *deviceId = rk_get_device_id();
    NSString *savedNick = [[NSUserDefaults standardUserDefaults] stringForKey:kRKDefaultsNickname]
        ?: [[NSUserDefaults standardUserDefaults] stringForKey:kRKDefaultsUsername];

    if (savedSession.length == 0 && savedNick.length == 0) {
        return;
    }

    _autoDeployCancelled = NO;
    _resumeTitleLabel.text = savedNick.length > 0
        ? [NSString stringWithFormat:@"Welcome back, %@", savedNick]
        : @"Restoring Device Session...";
    _resumeSubLabel.text = @"Auto-signing in without password...";
    _resumeCard.hidden = NO;
    [_resumeSpinner startAnimating];

    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    payload[@"device_id"] = deviceId;
    if (savedSession.length > 0) payload[@"session"] = savedSession;

    __weak typeof(self) weakSelf = self;
    [self postJSONPath:@"https://api.roslegacy.net/v2/ros/relaunch_mobile_ios_v2" body:payload completion:^(NSDictionary *json, NSInteger status, NSError *err) {
        __strong typeof(weakSelf) s = weakSelf;
        if (!s || s.autoDeployCancelled) return;
        [s.resumeSpinner stopAnimating];
        if (!err && status >= 200 && status < 300 && [json[@"success"] boolValue]) {
            NSString *ticket = json[@"auth"] ?: json[@"ticket"];
            NSString *sess = json[@"session"] ?: savedSession;
            NSString *user = json[@"username"] ?: savedNick ?: @"Survivor";
            NSString *nick = json[@"nickname"] ?: user;
            NSNumber *uid = [json[@"uid"] isKindOfClass:[NSNumber class]] ? json[@"uid"] : nil;
            if (ticket.length > 0) {
                s.resumeSubLabel.text = [NSString stringWithFormat:@"Signed in as @%@ — Entering lobby...", user];
                [s deployTicketToGame:ticket sessionToken:sess username:user nickname:nick uid:uid];
                return;
            }
        }
        if ([json[@"session_dead"] boolValue] || [json[@"logout"] boolValue]) {
            rk_clear_saved_session();
        }
        s.resumeCard.hidden = YES;
    }];
}

- (void)onSwitchAccountTapped {
    _autoDeployCancelled = YES;
    [_resumeSpinner stopAnimating];
    _resumeCard.hidden = YES;
    NSString *tok = rk_read_saved_session_token();
    NSMutableDictionary *body = [NSMutableDictionary dictionaryWithObject:rk_get_device_id() forKey:@"device_id"];
    if (tok.length > 0) body[@"session"] = tok;
    rk_clear_saved_session();
    [self postJSONPath:@"https://api.roslegacy.net/v2/ros/logout" body:body completion:^(__unused NSDictionary *j, __unused NSInteger st, __unused NSError *e) {}];
    [self showStatus:@"Signed out of this device. Sign in or create an account." isError:NO showCreateShortcut:NO];
}

- (void)onPrimaryTapped {
    if (_isBusy) return;
    [self endEditing:YES];

    NSString *deviceId = rk_get_device_id();
    __weak typeof(self) weakSelf = self;

    if (!_isRegisterMode) {
        NSString *user = [_loginUserField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
        NSString *pass = _loginPassField.text ?: @"";
        if (user.length == 0 || pass.length == 0) {
            [self showStatus:@"Enter your username and password." isError:YES showCreateShortcut:NO];
            return;
        }
        [self setBusyState:YES buttonTitle:@"AUTHENTICATING..."];
        NSDictionary *body = @{
            @"username": user,
            @"password": pass,
            @"device_id": deviceId,
            @"remember": @(_rememberSwitch.on)
        };
        [self postJSONPath:@"https://api.roslegacy.net/v2/ros/login_mobile_ios_v2" body:body completion:^(NSDictionary *json, NSInteger status, NSError *err) {
            __strong typeof(weakSelf) s = weakSelf;
            if (!s) return;
            [s setBusyState:NO buttonTitle:@"SIGN IN"];
            if (err || !json) {
                [s showStatus:@"Cannot reach server. Check Wi-Fi and try again." isError:YES showCreateShortcut:NO];
                return;
            }
            if (![json[@"success"] boolValue]) {
                BOOL reqReg = [json[@"require_register"] boolValue];
                NSString *msg = json[@"message"] ?: @"Sign in failed.";
                [s showStatus:msg isError:YES showCreateShortcut:reqReg];
                return;
            }
            NSString *ticket = json[@"auth"] ?: json[@"ticket"];
            NSString *sess = json[@"session"] ?: @"";
            NSString *uname = json[@"username"] ?: user;
            NSString *nick = json[@"nickname"] ?: uname;
            NSNumber *uid = [json[@"uid"] isKindOfClass:[NSNumber class]] ? json[@"uid"] : nil;
            [s showStatus:[NSString stringWithFormat:@"Signed in as %@. Entering lobby...", nick] isError:NO showCreateShortcut:NO];
            [s deployTicketToGame:ticket sessionToken:sess username:uname nickname:nick uid:uid];
        }];
    } else {
        NSString *user = [_regUserField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
        NSString *nick = [_regNickField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
        NSString *pass = _regPassField.text ?: @"";
        NSString *conf = _regConfirmField.text ?: @"";
        if (user.length < 3 || pass.length < 6) {
            [self showStatus:@"Username (3+ chars) and password (6+ chars) are required." isError:YES showCreateShortcut:NO];
            return;
        }
        if (![pass isEqualToString:conf]) {
            [self showStatus:@"Passwords do not match." isError:YES showCreateShortcut:NO];
            return;
        }
        [self setBusyState:YES buttonTitle:@"CREATING ACCOUNT..."];
        NSDictionary *body = @{
            @"username": user,
            @"nickname": nick.length > 0 ? nick : user,
            @"password": pass,
            @"confirm_password": conf,
            @"device_id": deviceId,
            @"remember": @(YES)
        };
        [self postJSONPath:@"https://api.roslegacy.net/v2/ros/register" body:body completion:^(NSDictionary *json, NSInteger status, NSError *err) {
            __strong typeof(weakSelf) s = weakSelf;
            if (!s) return;
            [s setBusyState:NO buttonTitle:@"CREATE ACCOUNT & ENTER"];
            if (err || !json) {
                [s showStatus:@"Cannot reach server. Check Wi-Fi and try again." isError:YES showCreateShortcut:NO];
                return;
            }
            if (![json[@"success"] boolValue]) {
                [s showStatus:(json[@"message"] ?: @"Account creation failed.") isError:YES showCreateShortcut:NO];
                return;
            }
            NSString *ticket = json[@"auth"] ?: json[@"ticket"];
            NSString *sess = json[@"session"] ?: @"";
            NSString *uname = json[@"username"] ?: user;
            NSString *rnick = json[@"nickname"] ?: uname;
            NSNumber *uid = [json[@"uid"] isKindOfClass:[NSNumber class]] ? json[@"uid"] : nil;
            [s showStatus:[NSString stringWithFormat:@"Created %@ (UID %@). Entering lobby...", uname, uid ?: @"-"] isError:NO showCreateShortcut:NO];
            [s deployTicketToGame:ticket sessionToken:sess username:uname nickname:rnick uid:uid];
        }];
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    if (textField == _loginUserField) {
        [_loginPassField becomeFirstResponder];
    } else if (textField == _loginPassField || textField == _regConfirmField) {
        [textField resignFirstResponder];
        [self onPrimaryTapped];
    } else if (textField == _regUserField) {
        [_regNickField becomeFirstResponder];
    } else if (textField == _regNickField) {
        [_regPassField becomeFirstResponder];
    } else if (textField == _regPassField) {
        [_regConfirmField becomeFirstResponder];
    }
    return YES;
}

- (void)onKeyboardChange:(NSNotification *)note {
    CGRect kb = [note.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    CGRect localKB = [self convertRect:kb fromView:nil];
    CGFloat overlap = (_cardContainer.frame.origin.y + _cardContainer.frame.size.height) - localKB.origin.y;
    if (overlap > 0) {
        _scrollView.contentInset = UIEdgeInsetsMake(0, 0, overlap + 24.0, 0);
        [_scrollView setContentOffset:CGPointMake(0, MIN(overlap + 12.0, 180.0)) animated:YES];
    }
}

- (void)onKeyboardHide:(NSNotification *)note {
    _scrollView.contentInset = UIEdgeInsetsZero;
    [_scrollView setContentOffset:CGPointMake(0, 0) animated:YES];
}

@end

@implementation RosKenorAuthController

+ (void)installLoginOverlayHooks {
    Class loginCls = objc_getClass("RosLoginVC");
    if (!loginCls) {
        NSLog(@"[RosKenorRedirect] RosLoginVC not found; skipping native UI overlay");
        return;
    }

    Method vdl = class_getInstanceMethod(loginCls, @selector(viewDidLoad));
    if (vdl) {
        IMP origVDL = method_getImplementation(vdl);
        IMP newVDL = imp_implementationWithBlock(^void(UIViewController *selfVC) {
            ((void (*)(id, SEL))origVDL)(selfVC, @selector(viewDidLoad));
            for (UIView *sub in selfVC.view.subviews) {
                sub.hidden = YES;
            }
            RosKenorAuthView *existing = objc_getAssociatedObject(selfVC, kRKOverlayAssocKey);
            if (!existing) {
                RosKenorAuthView *overlay = [[RosKenorAuthView alloc] initWithHostVC:selfVC frame:selfVC.view.bounds];
                [selfVC.view addSubview:overlay];
                objc_setAssociatedObject(selfVC, kRKOverlayAssocKey, overlay, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                [overlay attemptAutoResumeOnLaunch];
            }
        });
        method_setImplementation(vdl, newVDL);
    }

    Method layoutM = class_getInstanceMethod(loginCls, @selector(viewDidLayoutSubviews));
    if (layoutM) {
        IMP origLayout = method_getImplementation(layoutM);
        IMP newLayout = imp_implementationWithBlock(^void(UIViewController *selfVC) {
            ((void (*)(id, SEL))origLayout)(selfVC, @selector(viewDidLayoutSubviews));
            RosKenorAuthView *overlay = objc_getAssociatedObject(selfVC, kRKOverlayAssocKey);
            if (overlay) {
                overlay.frame = selfVC.view.bounds;
                [selfVC.view bringSubviewToFront:overlay];
            }
        });
        method_setImplementation(layoutM, newLayout);
    }
    NSLog(@"[RosKenorRedirect] Installed redesigned RosLoginVC overlay & device-session auto-login hooks");
}

@end

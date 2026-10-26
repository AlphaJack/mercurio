//! Windows toasts through WinRT, without the `windows` crate: six `combase.dll` functions and three COM interfaces, declared by hand.
//!
//! The sequence is the one `ToastNotificationManager` documents: activate an `XmlDocument`, `LoadXml` the payload, build a `ToastNotification` from it through its activation factory, then `CreateToastNotifierWithId(app_id).Show(toast)`.
//! Interface IDs and method order come from the Windows SDK metadata (the same values the `windows` crate generates).
#![expect(unsafe_code, reason = "calls into combase.dll and COM vtables")]

use std::ffi::c_void;
use std::ptr::null_mut;

use crate::error::{Error, Result};
use crate::transport::Toast;

type Hresult = i32;
type Hstring = *mut c_void;

/// `RO_INIT_MULTITHREADED`.
const RO_INIT_MULTITHREADED: i32 = 1;

/// The first method after `IUnknown` (3 slots) and `IInspectable` (3 slots).
const FIRST_METHOD: usize = 6;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl Guid {
    const fn from_u128(v: u128) -> Self {
        Self {
            data1: (v >> 96) as u32,
            data2: (v >> 80) as u16,
            data3: (v >> 64) as u16,
            data4: (v as u64).to_be_bytes(),
        }
    }
}

const IID_IXML_DOCUMENT: Guid = Guid::from_u128(0xf7f3a506_1e87_42d6_bcfb_b8c809fa5494);
const IID_IXML_DOCUMENT_IO: Guid = Guid::from_u128(0x6cd0e74e_ee65_4489_9ebf_ca43e87ba637);
const IID_ITOAST_NOTIFICATION_FACTORY: Guid = Guid::from_u128(0x04124b20_82c6_4229_b109_fd9ed4662b53);
const IID_ITOAST_NOTIFICATION_MANAGER_STATICS: Guid = Guid::from_u128(0x50ac103f_d235_4598_bbef_98fe4d1a3ad4);

#[link(name = "combase", kind = "raw-dylib")]
unsafe extern "system" {
    fn RoInitialize(init_type: i32) -> Hresult;
    fn RoUninitialize();
    fn RoActivateInstance(class_id: Hstring, instance: *mut *mut c_void) -> Hresult;
    fn RoGetActivationFactory(class_id: Hstring, iid: *const Guid, factory: *mut *mut c_void) -> Hresult;
    fn WindowsCreateString(source: *const u16, length: u32, string: *mut Hstring) -> Hresult;
    fn WindowsDeleteString(string: Hstring) -> Hresult;
}

fn check(hr: Hresult, step: &str) -> Result<()> {
    if hr < 0 { Err(Error::Service(format!("{step} failed with HRESULT 0x{:08X}", hr as u32))) } else { Ok(()) }
}

/// An owned `HSTRING`.
struct HString(Hstring);

impl HString {
    fn new(s: &str) -> Result<Self> {
        let wide: Vec<u16> = s.encode_utf16().collect();
        let len = u32::try_from(wide.len()).map_err(|_| Error::Service("toast text is too long".into()))?;
        let mut h = null_mut();
        // SAFETY: `wide` holds `len` UTF-16 units and outlives the call, which copies them.
        check(unsafe { WindowsCreateString(wide.as_ptr(), len, &mut h) }, "WindowsCreateString")?;
        Ok(Self(h))
    }
}

impl Drop for HString {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `WindowsCreateString` (or is null, which is the empty string).
        unsafe { WindowsDeleteString(self.0) };
    }
}

/// An owned COM interface pointer, released on drop.
struct Com(*mut c_void);

impl Com {
    /// Take ownership of an out-parameter once `hr` reports success.
    fn from_out(hr: Hresult, ptr: *mut c_void, step: &str) -> Result<Self> {
        check(hr, step)?;
        if ptr.is_null() {
            return Err(Error::Service(format!("{step} returned no object")));
        }
        Ok(Self(ptr))
    }

    /// Method `index` of the vtable.
    fn method(&self, index: usize) -> *const c_void {
        // SAFETY: `self.0` is a live COM object, whose first field is its vtable pointer; callers stay within the vtable.
        unsafe { *(*(self.0 as *const *const *const c_void)).add(index) }
    }

    fn query(&self, iid: &Guid, step: &str) -> Result<Com> {
        type QueryInterface = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> Hresult;
        let mut out = null_mut();
        // SAFETY: slot 0 of every COM vtable is `IUnknown::QueryInterface`.
        let hr = unsafe { std::mem::transmute::<*const c_void, QueryInterface>(self.method(0))(self.0, iid, &mut out) };
        Com::from_out(hr, out, step)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        type Release = unsafe extern "system" fn(*mut c_void) -> u32;
        // SAFETY: slot 2 of every COM vtable is `IUnknown::Release`; we own one reference.
        unsafe { std::mem::transmute::<*const c_void, Release>(self.method(2))(self.0) };
    }
}

fn activation_factory(class: &str, iid: &Guid) -> Result<Com> {
    let name = HString::new(class)?;
    let mut out = null_mut();
    // SAFETY: valid class name and IID; `out` receives an owned reference.
    let hr = unsafe { RoGetActivationFactory(name.0, iid, &mut out) };
    Com::from_out(hr, out, class)
}

fn show_toast(toast: &Toast) -> Result<()> {
    type LoadXml = unsafe extern "system" fn(*mut c_void, Hstring) -> Hresult;
    type CreateToastNotification = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> Hresult;
    type CreateToastNotifierWithId = unsafe extern "system" fn(*mut c_void, Hstring, *mut *mut c_void) -> Hresult;
    type Show = unsafe extern "system" fn(*mut c_void, *mut c_void) -> Hresult;

    let class = HString::new("Windows.Data.Xml.Dom.XmlDocument")?;
    let mut out = null_mut();
    // SAFETY: valid class name; `out` receives an owned `IInspectable`.
    let hr = unsafe { RoActivateInstance(class.0, &mut out) };
    let doc = Com::from_out(hr, out, "XmlDocument")?;
    let io = doc.query(&IID_IXML_DOCUMENT_IO, "IXmlDocumentIO")?;
    let xml = HString::new(&toast.xml)?;
    // SAFETY: `IXmlDocumentIO::LoadXml(HSTRING)` is its first method.
    check(unsafe { std::mem::transmute::<*const c_void, LoadXml>(io.method(FIRST_METHOD))(io.0, xml.0) }, "LoadXml")?;
    let doc = doc.query(&IID_IXML_DOCUMENT, "IXmlDocument")?;

    let factory = activation_factory("Windows.UI.Notifications.ToastNotification", &IID_ITOAST_NOTIFICATION_FACTORY)?;
    let mut out = null_mut();
    // SAFETY: `IToastNotificationFactory::CreateToastNotification(XmlDocument)` is its first method.
    let hr = unsafe {
        std::mem::transmute::<*const c_void, CreateToastNotification>(factory.method(FIRST_METHOD))(
            factory.0, doc.0, &mut out,
        )
    };
    let notification = Com::from_out(hr, out, "CreateToastNotification")?;

    let manager = activation_factory(
        "Windows.UI.Notifications.ToastNotificationManager",
        &IID_ITOAST_NOTIFICATION_MANAGER_STATICS,
    )?;
    let app_id = HString::new(&toast.app_id)?;
    let mut out = null_mut();
    // SAFETY: `IToastNotificationManagerStatics::CreateToastNotifierWithId(HSTRING)` is its second method.
    let hr = unsafe {
        std::mem::transmute::<*const c_void, CreateToastNotifierWithId>(manager.method(FIRST_METHOD + 1))(
            manager.0, app_id.0, &mut out,
        )
    };
    let notifier = Com::from_out(hr, out, "CreateToastNotifierWithId")?;
    // SAFETY: `IToastNotifier::Show(ToastNotification)` is its first method.
    check(
        unsafe {
            std::mem::transmute::<*const c_void, Show>(notifier.method(FIRST_METHOD))(notifier.0, notification.0)
        },
        "Show",
    )
}

/// Show `toast` on the calling thread, initialising WinRT for it when needed.
pub(crate) fn show(toast: &Toast) -> Result<()> {
    // SAFETY: plain call; a thread already in another apartment returns `RPC_E_CHANGED_MODE`, which still lets us call WinRT.
    let init = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    let res = show_toast(toast);
    if init >= 0 {
        // SAFETY: balances the successful `RoInitialize` above; every COM object was released when `show_toast` returned.
        unsafe { RoUninitialize() };
    }
    res
}

//! Integration tests for the example plugin (8.7) and derive macro (10.11/10.12).

use super::ExampleKdb;
use kurbu5_kdb_rs::{
    AccessMode, IterFlags, KdbModule, Krb5Context, LookupFlags, OpenMode,
    PrincipalAttributes, ServerType,
};

fn test_mode() -> OpenMode {
    OpenMode {
        access: AccessMode::ReadWrite,
        server: ServerType::Kdc,
    }
}

// ---------------------------------------------------------------------------
// Direct ExampleKdb tests (8.7)
// ---------------------------------------------------------------------------

#[test]
fn open_succeeds() {
    let tc = Krb5Context::new().unwrap();
    let kdb = tc.as_kdb();
    ExampleKdb::open(&kdb, "test", &[], test_mode()).unwrap();
}

#[test]
fn get_principal_known() {
    let tc = Krb5Context::new().unwrap();
    let kdb = tc.as_kdb();
    let module = ExampleKdb::open(&kdb, "test", &[], test_mode()).unwrap();

    let princ = kdb
        .parse_principal("krbtgt/EXAMPLE.COM@EXAMPLE.COM")
        .unwrap();
    let result = module
        .get_principal(&kdb, princ.as_ref(), LookupFlags::empty())
        .unwrap();

    assert!(result.is_some(), "expected krbtgt/EXAMPLE.COM to be found");
    let entry = result.unwrap();
    assert!(
        entry
            .as_ref()
            .attributes()
            .contains(PrincipalAttributes::REQUIRES_PRE_AUTH),
        "krbtgt entry should have REQUIRES_PRE_AUTH"
    );
}

#[test]
fn get_principal_unknown() {
    let tc = Krb5Context::new().unwrap();
    let kdb = tc.as_kdb();
    let module = ExampleKdb::open(&kdb, "test", &[], test_mode()).unwrap();

    let princ = kdb.parse_principal("nobody@EXAMPLE.COM").unwrap();
    let result = module
        .get_principal(&kdb, princ.as_ref(), LookupFlags::empty())
        .unwrap();

    assert!(result.is_none(), "unknown principal should return None");
}

#[test]
fn iterate_principals_visits_all() {
    let tc = Krb5Context::new().unwrap();
    let kdb = tc.as_kdb();
    let module = ExampleKdb::open(&kdb, "test", &[], test_mode()).unwrap();

    let mut count = 0usize;
    module
        .iterate_principals(&kdb, None, IterFlags::empty(), &mut |_entry| {
            count += 1;
            Ok(())
        })
        .unwrap();

    assert_eq!(count, 2, "open() seeds exactly 2 principals");
}

// ---------------------------------------------------------------------------
// Derive macro tests (10.11 / 10.12)
//
// OverlayKdb is a minimal single-field overlay wrapping ExampleKdb.
// The #[derive(KdbModule)] macro generates the full impl KdbModule block,
// delegating every method to self.backing except open and get_principal,
// which are provided as inherent methods renamed by #[kdb_method].
// ---------------------------------------------------------------------------

mod derive_tests {
    use super::super::ExampleKdb;
    use kurbu5_kdb_rs::{
        AccessMode, IterFlags, KdbContext, KdbError, KdbModule, Krb5Context,
        LookupFlags, OpenMode, PrincipalAttributes, PrincipalEntry,
        PrincipalRef, ServerType, kdb_impl, kdb_method,
    };

    #[derive(KdbModule)]
    #[kdb(delegate = backing)]
    struct OverlayKdb {
        backing: ExampleKdb,
    }

    #[kdb_impl]
    impl OverlayKdb {
        #[kdb_method]
        fn open(
            ctx: &KdbContext<'_>,
            conf_section: &str,
            db_args: &[&str],
            mode: OpenMode,
        ) -> Result<Self, KdbError> {
            ExampleKdb::open(ctx, conf_section, db_args, mode)
                .map(|backing| OverlayKdb { backing })
        }

        #[kdb_method]
        fn get_principal(
            &self,
            ctx: &KdbContext<'_>,
            search_for: PrincipalRef<'_>,
            flags: LookupFlags,
        ) -> Result<Option<PrincipalEntry>, KdbError> {
            self.backing.get_principal(ctx, search_for, flags)
        }
    }

    fn test_mode() -> OpenMode {
        OpenMode {
            access: AccessMode::ReadWrite,
            server: ServerType::Kdc,
        }
    }

    #[test]
    fn overlay_open_succeeds() {
        let tc = Krb5Context::new().unwrap();
        let kdb = tc.as_kdb();
        OverlayKdb::open(&kdb, "test", &[], test_mode()).unwrap();
    }

    #[test]
    fn overlay_get_principal_delegates() {
        let tc = Krb5Context::new().unwrap();
        let kdb = tc.as_kdb();
        let module = OverlayKdb::open(&kdb, "test", &[], test_mode()).unwrap();
        let princ = kdb
            .parse_principal("krbtgt/EXAMPLE.COM@EXAMPLE.COM")
            .unwrap();
        let entry = module
            .get_principal(&kdb, princ.as_ref(), LookupFlags::empty())
            .unwrap();
        assert!(entry.is_some(), "overlay should find krbtgt via backing");
        assert!(
            entry
                .unwrap()
                .as_ref()
                .attributes()
                .contains(PrincipalAttributes::REQUIRES_PRE_AUTH),
        );
    }

    #[test]
    fn overlay_iterate_delegates() {
        let tc = Krb5Context::new().unwrap();
        let kdb = tc.as_kdb();
        let module = OverlayKdb::open(&kdb, "test", &[], test_mode()).unwrap();
        let mut count = 0usize;
        module
            .iterate_principals(&kdb, None, IterFlags::empty(), &mut |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 2, "delegated iterate should yield 2 entries");
    }
}

#![allow(clippy::unwrap_used, clippy::expect_used)]
use forgeguard_core::Fgrn;
use serde_json::Value;

fn fixture(name: &str) -> Vec<Value> {
    let path = concat_path(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn concat_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fgrn")
        .join(name)
}

#[test]
fn valid_fixtures_parse_and_round_trip() {
    for case in fixture("valid.json") {
        let input = case["input"].as_str().unwrap();
        let fgrn = Fgrn::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(fgrn.to_string(), input, "round-trip: {input}");
        assert_eq!(
            fgrn.organization().as_str(),
            case["organization"].as_str().unwrap()
        );
        assert_eq!(fgrn.kind().as_str(), case["kind"].as_str().unwrap());
        assert_eq!(fgrn.id().as_str(), case["id"].as_str().unwrap());
        if let Some(rt) = case.get("resource_type") {
            let (resource_type, native_id) = fgrn.resource_parts().unwrap();
            assert_eq!(resource_type.as_str(), rt.as_str().unwrap());
            assert_eq!(native_id.as_str(), case["native_id"].as_str().unwrap());
        }
    }
}

#[test]
fn invalid_fixtures_fail_to_parse() {
    for case in fixture("invalid.json") {
        let input = case["input"].as_str().unwrap();
        assert!(Fgrn::parse(input).is_err(), "should reject: {input}");
    }
}

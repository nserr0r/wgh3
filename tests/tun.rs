use ipnet::IpNet;
use std::time::Duration;
use wgh3::network::tun::Tun;

#[tokio::test]
#[ignore = "требует root"]
async fn create_tun() {
    let address: IpNet = "10.99.99.1/24".parse().unwrap();
    let tun = Tun::new("wgh3test", address, 1380).expect("создание TUN");
    assert_eq!(tun.name(), "wgh3test");
}

#[tokio::test]
#[ignore = "требует root"]
async fn tun_visible_in_kernel() {
    let address: IpNet = "10.99.99.1/24".parse().unwrap();
    let tun = Tun::new("wgh3probe", address, 1380).expect("создание TUN");

    tokio::time::sleep(Duration::from_secs(3)).await;

    drop(tun);
}

use rocket::{ Request, request::{FromRequest, Outcome}};
use rocket_airlock::Airlock;
use crate::hatch;


#[derive(Debug)]
pub(crate) struct User {
    pub(crate) name: String
}

#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();

    // RUSTC BUG (rustc 1.46.0-nightly (346aec9b0 2020-07-11) running on x86_64-pc-windows-msvc)
    async fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let mut cookies = request.cookies();
        match cookies.get_private("logged_in") {
            Some(logged_in) if request.guard::<Airlock<hatch::SimpleHatch>>().await.expect("Hatch 'SimpleHatch' was not installed into the airlock.")
                                            .hatch.is_session_expired(&logged_in.value().to_string())
            => {
                Outcome::Success(User{ name: logged_in.value().to_string() })
            },
            _ => return Outcome::Forward(())
        }
    }
}

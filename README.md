# Telegram Oauth server validation in rust

Telegram Login for Websites

![Image description](https://core.telegram.org/file/811140220/1a02/WFoFUXRl_C8.20012/170c02fae7a0c638aa)

# Prerequisites:

Follow [official telegram instructions](https://core.telegram.org/widgets/login) to
 - register your telegram bot
 - define domain name for **telegram login widget**
 - insert **telegram login widget** javascript snippet into your website
 - handle sending telegram Oauth data to server

# Server side validation example:
1. Fill TelegramOauth struct using data from **telegram login widget**
2. Call verify function

```
let telegram_token = "000000000:DUMMY_A_SUPER_SECRET_TELEGRAM_TOKEN";

let telegram_oauth = TelegramOauth {
    hash: "334716aa3e904291b6c7d6d464446a5d2b00bc30359fa0afb336e442ed11339e",
    id: 123456789,
    username: Some("username"),
    first_name: Some("DummyName"),
    last_name: Some("DummySecondName"),
    photo_url: Some("https://t.me/i/userpic/000/dummy-your-user-profile-picture-path.jpg"),
    auth_date: u64::MAX,
};

let verification_result = telegram_oauth.verify(telegram_token, 86400);

println!("{:?}", res);
```

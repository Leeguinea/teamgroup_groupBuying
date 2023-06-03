package com.example.GroupBuying.kakaomodel;
import lombok.Data;

import javax.annotation.Generated;

@Generated("jsonschema2pojo")
@Data
public class KakaoProfile {

    public Long id;
    public String connected_at;
    public Properties properties;
    public KakaoAccount kakao_account;

    @Data
    public class Properties {

        public String nickname;
        public String profile_image;
        public String thumbnail_image;

    }
    @Data
    public class KakaoAccount {
        public Boolean profile_image_needs_agreement;
        public Profile profile;
        public Boolean has_email;
        public Boolean email_needs_agreement;
        public Boolean is_email_valid;
        public Boolean is_email_verified;
        public String email;
        public Boolean has_birthday;
        public Boolean birthday_needs_agreement;
        public String birthday;
        public String birthday_type;
        @Data
        public class Profile {
            public String thumbnail_image_url;
            public String profile_image_url;
            public Boolean is_default_image;

        }
    }
}



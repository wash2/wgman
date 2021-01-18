-- Table: public.User

-- DROP TABLE public."User";

CREATE TABLE public."User"
(
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    name text COLLATE pg_catalog."default" NOT NULL,
    is_admin boolean NOT NULL,
    CONSTRAINT "User_pkey" PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE public."User"
    OWNER to postgres;

with app.app_context():
    try:
        db.create_all()
        print("✅ Database tables created")

        # Fix missing columns
        columns_to_add = [
            "class_id INTEGER",
            "tenant_id INTEGER",
            "term_registered VARCHAR(20)",
            "status VARCHAR(50) DEFAULT 'active'",
            "added_by VARCHAR(255)",
            "last_updated TIMESTAMP"
        ]

        with db.engine.connect() as conn:
            for column in columns_to_add:
                try:
                    conn.execute(text(f"ALTER TABLE students ADD COLUMN IF NOT EXISTS {column}"))
                    conn.commit()
                except:
                    pass

            try:
                conn.execute(text("ALTER TABLE students RENAME COLUMN class TO class_id"))
                conn.commit()
            except:
                pass

        # ============ CREATE SEPARATE TENANTS ============
        
        tenants_data = [
            {"name": "Raven School", "admin_email": "admin1@school.com", "admin_name": "Raven School"},
            {"name": "Eagle School", "admin_email": "admin2@school.com", "admin_name": "Eagle School"},
            {"name": "Hawk School", "admin_email": "admin3@school.com", "admin_name": "Hawk School"}
        ]
        
        for t_data in tenants_data:
            # Create or get tenant
            tenant = Tenant.query.filter_by(name=t_data["name"]).first()
            if not tenant:
                tenant = Tenant(name=t_data["name"])
                db.session.add(tenant)
                db.session.commit()
                print(f"✅ Created tenant: {t_data['name']}")
            
            # Create admin user with default password pass123
            email = t_data["admin_email"]
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(
                    email=email,
                    name=t_data["admin_name"],
                    password_hash=hash_password('pass123'),
                    role='super_admin',
                    tenant_id=tenant.id
                )
                db.session.add(user)
                print(f"✅ Created admin: {email} | Password: pass123 | Tenant: {t_data['name']}")
            else:
                # Update tenant_id
                user.tenant_id = tenant.id
                user.name = t_data["admin_name"]
                print(f"✅ Updated admin: {email} | Tenant: {t_data['name']}")
        
        db.session.commit()
        print("✅ Multi-tenant database initialized")
        print("📝 Default Password for all admins: pass123")
        
    except Exception as e:
        print(f"⚠️ Init error: {e}")

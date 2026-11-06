# E-commerce Analysis Profile

This profile extends the repository workflow with storefront, API, checkout, payment, administrative, and third-party integration context. It does not authorize active testing.

## Required Scope Information

- Repository, revision, storefronts, APIs, and administrative components in scope
- Commerce platform and deployment model
- Payment flow and whether cardholder data enters, crosses, or is stored by the assessed system
- Payment service providers and hosted checkout boundaries
- First-party and third-party scripts on payment-related pages
- Plugins, themes, extensions, webhooks, pixels, tag managers, and build pipelines
- Explicitly excluded systems and data

PCI DSS applies only when the architecture and payment-data flow place the component in scope. Platform marketing claims or a provider's compliance status do not automatically remove merchant responsibilities.

## Static Review Areas

### Identity and administration

- Authentication, session handling, password reset, MFA, and account recovery
- Role and permission checks for customers, support staff, merchants, and administrators
- Administrative endpoints, bulk actions, imports, and impersonation features

### Storefront and content

- Stored, reflected, and DOM-based injection paths
- Template rendering, rich text, reviews, profiles, CMS content, and uploaded files
- Content Security Policy and unsafe script allowances

### APIs and business logic

- Object-level and function-level authorization
- Cart ownership, price and quantity integrity, discounts, coupons, gift cards, credits, inventory, and refunds
- Checkout state transitions and server-side recalculation
- REST, GraphQL, mobile, and partner API consistency

### Payments and sensitive data

- PAN, CVV, payment tokens, personal data, and authentication data in code, logs, analytics, queues, and error messages
- Payment callbacks, redirect validation, webhook signatures, replay protection, and idempotency
- Trust boundaries between hosted checkout, merchant code, gateways, and third parties

### Client-side script security

- Inventory and authorization of scripts on payment-related pages
- Integrity and change detection for first-party and third-party scripts
- Tag managers, pixels, widgets, compromised dependencies, and build-time injection paths
- Unexpected data collection or transmission from payment and account pages

The exact interpretation of PCI DSS requirements, including payment-page script controls, must be verified against the current official PCI SSC publication.

### Dependencies and supply chain

- Locked and transitive dependencies
- Plugins, themes, extensions, container images, and CI actions
- Typosquatting, abandoned packages, provenance, release integrity, and known exploited vulnerabilities
- Secrets and excessive permissions in CI/CD workflows

### Configuration and operations

- Debug modes, default credentials, insecure CORS, public storage, and exposed administrative interfaces
- Security headers, TLS assumptions, cookie attributes, and cache behavior
- Logging, monitoring, alerting, backups, and recovery-sensitive configuration

## Active Validation Boundary

Requests to a deployed storefront, API, checkout, webhook, or administrative panel use the `active` profile and require explicit authorization naming the targets, techniques, time window, test accounts, data-handling rules, and stop conditions.

Static analysis may propose safe validation steps, but it must not silently execute them against a live service.

## Reporting Priorities

Prioritize validated findings that affect authorization, payment integrity, customer data, administrative access, third-party script trust, or supply-chain compromise. Report compliance mappings as context, not as a claim of certification or full compliance.

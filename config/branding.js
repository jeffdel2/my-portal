/**
 * Branding Configuration
 * Centralized configuration for Partner Portal branding and content.
 * Modify these values to white-label the application for different deployments.
 */

module.exports = {
  // Company Identity
  companyName: 'Partner Portal',
  tagline: 'Streamlined B2B Partner Relationship Management',
  description: 'Empowering business partnerships through innovative technology and dedicated support. Join thousands of partners who trust our platform to grow their business.',

  // Color Scheme
  colors: {
    primary: '#0066CC',
    secondary: '#00CC88',
    accent: '#FF6B35',
    dark: '#2C3E50',
    light: '#ECF0F1'
  },

  // Partner Tier Definitions
  partnerTiers: {
    bronze: {
      name: 'Standard Partner',
      price: 'Free',
      features: [
        'Access to partner portal',
        'Basic marketplace listing',
        'Monthly performance reports',
        'Email support (48h response)',
        'Standard commission rates',
        'Quarterly business reviews'
      ],
      icon: 'fa-award',
      badge: 'text-bg-secondary'
    },
    silver: {
      name: 'Premium Partner',
      price: '$499/month',
      features: [
        'Everything in Standard Partner',
        'Featured marketplace placement',
        'Priority lead distribution',
        'Weekly performance analytics',
        'Priority email & chat support (24h)',
        'Enhanced commission rates',
        'Co-marketing opportunities',
        'Monthly business reviews'
      ],
      icon: 'fa-medal',
      badge: 'text-bg-primary',
      recommended: true
    },
    gold: {
      name: 'Elite Partner',
      price: 'Custom Pricing',
      features: [
        'Everything in Premium Partner',
        'Exclusive territory rights',
        'Dedicated account manager',
        'Real-time analytics dashboard',
        '24/7 priority phone support',
        'Maximum commission rates',
        'Joint marketing campaigns',
        'Custom API integrations',
        'White-label opportunities',
        'Weekly strategic reviews'
      ],
      icon: 'fa-crown',
      badge: 'text-bg-warning'
    }
  },

  // Trust Statistics
  statistics: {
    networkPartners: '5,000+',
    yearsInBusiness: '25+',
    marketPosition: '#1 Platform',
    customerSatisfaction: '98%'
  },

  // Dashboard Metrics (sample data for landing page)
  sampleMetrics: {
    revenue: '$185K',
    revenueLabel: 'Monthly Revenue',
    leads: '1,250',
    leadsLabel: 'Active Leads',
    partners: '47',
    partnersLabel: 'Network Connections',
    growth: '+23%',
    growthLabel: 'Quarter Growth'
  },

  // Success Stories
  successStories: [
    {
      company: 'TechSolutions Inc',
      logo: '/images/partner-logo-1.png',
      tier: 'Elite Partner',
      testimonial: 'Partnering with this platform has transformed our business. We\'ve seen a 300% increase in qualified leads and our revenue has grown significantly.',
      metrics: {
        revenue: '+$2.4M',
        leads: '3,500+',
        growth: '+300%'
      },
      contact: {
        name: 'Sarah Johnson',
        title: 'VP of Business Development'
      }
    },
    {
      company: 'Global Services Group',
      logo: '/images/partner-logo-2.png',
      tier: 'Premium Partner',
      testimonial: 'The partner portal\'s tools and support have been exceptional. We\'ve expanded into new markets and built valuable relationships with other partners in the network.',
      metrics: {
        revenue: '+$850K',
        leads: '1,800+',
        growth: '+175%'
      },
      contact: {
        name: 'Michael Chen',
        title: 'Director of Partnerships'
      }
    },
    {
      company: 'Enterprise Solutions Co',
      logo: '/images/partner-logo-3.png',
      tier: 'Elite Partner',
      testimonial: 'Outstanding platform with incredible support. The dedicated account management and exclusive territory rights have given us a competitive advantage in our market.',
      metrics: {
        revenue: '+$1.8M',
        leads: '2,400+',
        growth: '+240%'
      },
      contact: {
        name: 'Jennifer Martinez',
        title: 'Chief Revenue Officer'
      }
    }
  ],

  // Resource Categories
  resources: [
    {
      title: 'Partner Directory',
      icon: 'fa-address-book',
      description: 'Browse our complete network of partners, explore partnership opportunities, and connect with businesses in your industry.'
    },
    {
      title: 'Training Programs',
      icon: 'fa-graduation-cap',
      description: 'Access comprehensive training materials, webinars, and certification programs to maximize your partnership success.'
    },
    {
      title: 'Marketing Support',
      icon: 'fa-bullhorn',
      description: 'Leverage co-marketing opportunities, promotional materials, and marketing resources to grow your business presence.'
    },
    {
      title: 'Partner Network',
      icon: 'fa-users',
      description: 'Connect with other partners, share best practices, and collaborate on joint opportunities through our partner community.'
    }
  ],

  // Footer Configuration
  footer: {
    tagline: 'Empowering business partnerships through innovation',
    description: 'We offer comprehensive partner relationship management tools, networking opportunities, and dedicated support to help your business thrive.',

    features: [
      {
        icon: 'bi-lightning-charge',
        title: 'Fast Onboarding',
        description: 'Get started quickly with our streamlined partner onboarding process'
      },
      {
        icon: 'bi-shield-check',
        title: 'Secure Platform',
        description: 'Enterprise-grade security protecting your business data'
      },
      {
        icon: 'bi-headset',
        title: '24/7 Support',
        description: 'Answers to any partner inquiry around the clock'
      }
    ],

    sections: {
      about: {
        title: 'About',
        links: [
          { text: 'Company', url: '/about' },
          { text: 'Our Team', url: '/team' },
          { text: 'Careers', url: '/careers' },
          { text: 'Press', url: '/press' }
        ]
      },
      partners: {
        title: 'Partner Resources',
        links: [
          { text: 'Partner Portal', url: '/partners' },
          { text: 'Become a Partner', url: '/partners/register' },
          { text: 'Login', url: '/partners/login' },
          { text: 'Support Center', url: '/partners/support' }
        ]
      },
      legal: {
        title: 'Legal',
        links: [
          { text: 'Privacy Policy', url: '/privacy' },
          { text: 'Terms of Service', url: '/terms' },
          { text: 'Partner Agreement', url: '/partner-agreement' },
          { text: 'Security', url: '/security' }
        ]
      }
    },

    contact: {
      email: 'partners@example.com',
      phone: '1-800-PARTNER',
      address: '123 Business Avenue, Suite 100, City, ST 12345'
    },

    social: {
      twitter: '#',
      linkedin: '#',
      facebook: '#',
      youtube: '#'
    },

    copyright: 'Partner Portal. All rights reserved.'
  }
};

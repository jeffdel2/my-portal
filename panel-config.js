/**
 * Dynamic Panel Configuration
 * Defines available panel types and their properties
 */

const PANEL_TYPES = {
  'consumer-insights': {
    id: 'consumer-insights',
    name: 'Consumer Insights Panel',
    description: 'Share your shopping habits and preferences to help brands understand consumer behavior',
    category: 'shopping',
    icon: 'fas fa-shopping-cart',
    color: '#0066CC',
    rewards: {
      base: 5,
      bonus: 10,
      currency: 'USD'
    },
    requirements: {
      minAge: 18,
      maxPanels: 3
    },
    activities: [
      'Receipt scanning',
      'Product reviews',
      'Shopping surveys',
      'Brand preference studies'
    ]
  },
  'media-consumption': {
    id: 'media-consumption',
    name: 'Media Consumption Panel',
    description: 'Track your TV, streaming, and digital media consumption habits',
    category: 'media',
    icon: 'fas fa-tv',
    color: '#6B46C1',
    rewards: {
      base: 8,
      bonus: 15,
      currency: 'USD'
    },
    requirements: {
      minAge: 16,
      maxPanels: 2
    },
    activities: [
      'TV viewing tracking',
      'Streaming app usage',
      'Media preference surveys',
      'Content rating studies'
    ]
  },
  'product-testing': {
    id: 'product-testing',
    name: 'Product Testing Panel',
    description: 'Test new products and provide feedback to help improve consumer goods',
    category: 'testing',
    icon: 'fas fa-flask',
    color: '#059669',
    rewards: {
      base: 15,
      bonus: 25,
      currency: 'USD'
    },
    requirements: {
      minAge: 21,
      maxPanels: 1
    },
    activities: [
      'Product testing',
      'Taste testing',
      'Usability studies',
      'Product feedback surveys'
    ]
  },
  'lifestyle-research': {
    id: 'lifestyle-research',
    name: 'Lifestyle Research Panel',
    description: 'Share insights about your lifestyle, health, and wellness habits',
    category: 'lifestyle',
    icon: 'fas fa-heart',
    color: '#DC2626',
    rewards: {
      base: 7,
      bonus: 12,
      currency: 'USD'
    },
    requirements: {
      minAge: 18,
      maxPanels: 2
    },
    activities: [
      'Health surveys',
      'Fitness tracking',
      'Wellness studies',
      'Lifestyle questionnaires'
    ]
  },
  'tech-usage': {
    id: 'tech-usage',
    name: 'Technology Usage Panel',
    description: 'Help tech companies understand how people use digital devices and services',
    category: 'technology',
    icon: 'fas fa-mobile-alt',
    color: '#7C3AED',
    rewards: {
      base: 6,
      bonus: 12,
      currency: 'USD'
    },
    requirements: {
      minAge: 16,
      maxPanels: 2
    },
    activities: [
      'App usage tracking',
      'Device usage surveys',
      'Tech preference studies',
      'Digital behavior analysis'
    ]
  }
};

const PANEL_CATEGORIES = {
  'shopping': {
    name: 'Shopping & Consumer',
    description: 'Panels focused on shopping habits and consumer behavior',
    icon: 'fas fa-shopping-bag'
  },
  'media': {
    name: 'Media & Entertainment',
    description: 'Panels tracking media consumption and entertainment preferences',
    icon: 'fas fa-play-circle'
  },
  'testing': {
    name: 'Product Testing',
    description: 'Exclusive panels for testing new products and services',
    icon: 'fas fa-vial'
  },
  'lifestyle': {
    name: 'Lifestyle & Wellness',
    description: 'Panels focused on health, wellness, and lifestyle habits',
    icon: 'fas fa-leaf'
  },
  'technology': {
    name: 'Technology & Digital',
    description: 'Panels tracking technology usage and digital behavior',
    icon: 'fas fa-laptop'
  }
};

/**
 * Get all available panel types
 */
function getAllPanelTypes() {
  return Object.values(PANEL_TYPES);
}

/**
 * Get panel types by category
 */
function getPanelTypesByCategory(category) {
  return Object.values(PANEL_TYPES).filter(panel => panel.category === category);
}

/**
 * Get a specific panel type by ID
 */
function getPanelType(panelId) {
  return PANEL_TYPES[panelId];
}

/**
 * Get all panel categories
 */
function getAllCategories() {
  return Object.values(PANEL_CATEGORIES);
}

/**
 * Get panel recommendations based on user profile
 */
function getRecommendedPanels(userProfile = {}) {
  const { age, interests = [], currentPanels = [] } = userProfile;
  
  let recommendations = Object.values(PANEL_TYPES);
  
  // Filter by age requirements
  if (age) {
    recommendations = recommendations.filter(panel => age >= panel.requirements.minAge);
  }
  
  // Filter out panels user is already in
  recommendations = recommendations.filter(panel => 
    !currentPanels.some(currentPanel => currentPanel.panelId === panel.id)
  );
  
  // Sort by relevance (could be enhanced with ML)
  recommendations.sort((a, b) => {
    // Prioritize panels with higher base rewards
    return b.rewards.base - a.rewards.base;
  });
  
  return recommendations;
}

/**
 * Check if user can join a specific panel
 */
function canUserJoinPanel(userId, panelId, currentPanels = []) {
  const panel = getPanelType(panelId);
  if (!panel) return { canJoin: false, reason: 'Panel not found' };
  
  // Check if user is already in this panel
  const alreadyInPanel = currentPanels.some(p => p.panelId === panelId);
  if (alreadyInPanel) {
    return { canJoin: false, reason: 'Already enrolled in this panel' };
  }
  
  // Check max panels limit
  const maxPanels = Math.max(...Object.values(PANEL_TYPES).map(p => p.requirements.maxPanels));
  if (currentPanels.length >= maxPanels) {
    return { canJoin: false, reason: 'Maximum number of panels reached' };
  }
  
  return { canJoin: true };
}

module.exports = {
  PANEL_TYPES,
  PANEL_CATEGORIES,
  getAllPanelTypes,
  getPanelTypesByCategory,
  getPanelType,
  getAllCategories,
  getRecommendedPanels,
  canUserJoinPanel
};

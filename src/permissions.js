export const ROLES = [
  { id: 'administrator', label: 'Administrator' },
  { id: 'pracownik', label: 'Pracownik' },
  { id: 'gosc', label: 'Gość' },
];

export const PERMISSIONS = [
  { id: 'profile.self', group: 'Konto', label: 'Własny profil, zmiana hasła i drugi składnik TOTP' },
  { id: 'announcements.read_public', group: 'Ogłoszenia', label: 'Odczyt ogłoszeń ogólnodostępnych' },
  { id: 'announcements.read_internal', group: 'Ogłoszenia', label: 'Odczyt ogłoszeń wewnętrznych' },
  { id: 'announcements.create', group: 'Ogłoszenia', label: 'Dodawanie ogłoszeń' },
  { id: 'announcements.update_own', group: 'Ogłoszenia', label: 'Edycja własnych ogłoszeń' },
  { id: 'announcements.update_any', group: 'Ogłoszenia', label: 'Edycja dowolnego ogłoszenia' },
  { id: 'announcements.delete_own', group: 'Ogłoszenia', label: 'Usuwanie własnych ogłoszeń' },
  { id: 'announcements.delete_any', group: 'Ogłoszenia', label: 'Usuwanie dowolnego ogłoszenia' },
  { id: 'documents.read', group: 'Dokumenty', label: 'Odczyt dokumentów wewnętrznych' },
  { id: 'documents.create', group: 'Dokumenty', label: 'Dodawanie dokumentów' },
  { id: 'documents.update_own', group: 'Dokumenty', label: 'Edycja własnych dokumentów' },
  { id: 'documents.update_any', group: 'Dokumenty', label: 'Edycja dowolnego dokumentu' },
  { id: 'documents.delete_own', group: 'Dokumenty', label: 'Usuwanie własnych dokumentów' },
  { id: 'documents.delete_any', group: 'Dokumenty', label: 'Usuwanie dowolnego dokumentu' },
  { id: 'users.read', group: 'Administracja', label: 'Lista użytkowników i podgląd zapisu hasła' },
  { id: 'users.create', group: 'Administracja', label: 'Zakładanie kont i nadawanie hasła jednorazowego' },
  { id: 'users.update', group: 'Administracja', label: 'Edycja danych i roli' },
  { id: 'users.block', group: 'Administracja', label: 'Blokowanie i odblokowanie kont' },
  { id: 'users.delete', group: 'Administracja', label: 'Usuwanie kont' },
  { id: 'users.reset_password', group: 'Administracja', label: 'Reset hasła hasłem jednorazowym' },
  { id: 'settings.manage', group: 'Administracja', label: 'Polityka haseł, ważność hasła i czas sesji' },
  { id: 'audit.read', group: 'Administracja', label: 'Odczyt dziennika zdarzeń' },
];

const PRACOWNIK = [
  'profile.self',
  'announcements.read_public',
  'announcements.read_internal',
  'announcements.create',
  'announcements.update_own',
  'announcements.delete_own',
  'documents.read',
  'documents.create',
  'documents.update_own',
  'documents.delete_own',
];

const GOSC = ['profile.self', 'announcements.read_public'];

export const GRANTS = {
  administrator: new Set(PERMISSIONS.map((item) => item.id)),
  pracownik: new Set(PRACOWNIK),
  gosc: new Set(GOSC),
};

export function roleLabel(role) {
  return ROLES.find((item) => item.id === role)?.label || role;
}

export function can(role, permission) {
  return GRANTS[role]?.has(permission) ?? false;
}

export function canEditOwn(user, row, ownPermission, anyPermission) {
  if (!user || !row) return false;
  if (can(user.role, anyPermission)) return true;
  return can(user.role, ownPermission) && row.author_id === user.id;
}

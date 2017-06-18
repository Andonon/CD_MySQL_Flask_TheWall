select m.message,DATE_FORMAT(m.created_at,'%M %D %Y') as datecreated,u.first_name,u.last_name
from messages m join users u on m.user_id = u.id
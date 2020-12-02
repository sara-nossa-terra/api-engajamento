<?php

namespace App\Repositories;

use App\Entity\User as Leader;
use App\Repositories\Contracts\LeaderRepositoryInterface;

class LeaderRepository implements LeaderRepositoryInterface
{
    protected $entity;

    public function __construct(Leader $leader)
    {
        $this->entity = $leader;
    }

    public function all()
    {
        return $this->entity->all();
    }

    public function find(int $id)
    {
        return $this->entity
            ->find($id);
    }

    public function createLeader(array $data)
    {
        return $this->entity->create($data);
    }

    public function updateLeader(array $data)
    {
        return $this->find($data['id'])->update($data);
    }

    public function deleteLeader(int $id)
    {
        return $this->find($id)->delete();
    }
}